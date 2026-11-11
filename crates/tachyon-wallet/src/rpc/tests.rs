use super::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::Instant,
};

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let start = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "RPC did not connect"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

#[test]
fn cancellation_interrupts_both_headers_and_response_body() -> Result<()> {
    for partial_body in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}", listener.local_addr()?);
        let control = Control::new(true);
        let worker_control = control.clone();
        let (done, result) = mpsc::channel();
        let worker = thread::spawn(move || {
            let rpc = Rpc::new(&url, None, &worker_control).unwrap();
            done.send(rpc.hash(1)).unwrap();
        });
        let mut connection = accept(&listener);
        connection.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut request = [0; 2048];
        assert!(connection.read(&mut request)? > 0);
        if partial_body {
            connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n{")?;
        }
        let started = Instant::now();
        control.cancellation.cancel();
        let error = result.recv_timeout(Duration::from_secs(3))?.unwrap_err();
        assert!(format!("{error:#}").contains("cancelled"));
        assert!(started.elapsed() < Duration::from_secs(3));
        worker.join().unwrap();
    }
    Ok(())
}

#[test]
fn request_deadline_covers_stalled_body_without_a_signal() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}", listener.local_addr()?);
    let (done, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut rpc = Rpc::new(&url, None, &Control::new(true)).unwrap();
        rpc.client = Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();
        done.send(rpc.hash(1)).unwrap();
    });
    let mut connection = accept(&listener);
    connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n{")?;
    let error = result.recv_timeout(Duration::from_secs(5))?.unwrap_err();
    assert!(format!("{error:#}").contains("reading response failed"));
    assert!(error.downcast_ref::<reqwest::Error>().unwrap().is_timeout());
    worker.join().unwrap();
    Ok(())
}

#[test]
fn batch_results_follow_request_order_whatever_the_reply_order() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}", listener.local_addr()?);
    let (done, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        let rpc = Rpc::new(&url, None, &Control::new(true)).unwrap();
        done.send(rpc.batch::<String>("getblockhash", vec![json!([1]), json!([2])]))
            .unwrap();
    });
    let mut connection = accept(&listener);
    connection.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request = [0; 2048];
    assert!(connection.read(&mut request)? > 0);
    let body =
        r#"[{"id":1,"result":"second","error":null},{"id":0,"result":"first","error":null}]"#;
    connection.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )?;
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5))??,
        ["first", "second"]
    );
    worker.join().unwrap();
    Ok(())
}
