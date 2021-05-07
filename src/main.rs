use std::io::{Error, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str;
use std::thread;

use sha1::Sha1;

const HASH_KEY: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn main() {
    let addr = "127.0.0.1:8080";

    let listener = TcpListener::bind(addr)
        .map_err(|e| panic!("cannot listen on {}: {:?}", addr, e))
        .unwrap();

    println!("listening on http://{}", addr);

    for stream in listener.incoming().flatten() {
        thread::spawn(|| {
            handle_client(stream).unwrap();
        });
    }
}

fn handle_client(mut stream: TcpStream) -> Result<(), Error> {
    let mut buf = [0; 4096];
    stream.read(&mut buf)?;

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&buf).expect("cannot parse request");

    let path = req.path.unwrap();

    match path {
        "/" => {
            let data = concat!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n",
                include_str!("./index.html")
            );

            stream.write_all(data.as_bytes())?;
            Ok(())
        }

        "/websocket" => {
            let token_bytes = req
                .headers
                .iter()
                .find(|&x| x.name == "Sec-WebSocket-Key")
                .expect("not found \"Sec-WebSocket-Key header\"")
                .value;

            let joined_token = format!("{}{}", str::from_utf8(token_bytes).unwrap(), HASH_KEY);

            let mut hasher = Sha1::new();
            hasher.update(joined_token.as_bytes());
            let sha1_base64 = base64::encode(hasher.digest().bytes());

            let data = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: chat\r\n\r\n", sha1_base64);

            println!("======== Response Header ========");
            println!("{}", data);
            println!("=================================");

            stream.write_all(data.as_bytes())?;

            let mut msg_buf = [0; 1024];
            while stream.read(&mut msg_buf).is_ok() {
                let opcode = msg_buf[0] & 0x0f;

                if opcode == 1 {
                    let payload_length = (msg_buf[1] % 128) as usize;
                    let mask = &msg_buf[2..=5];
                    let mut payload_raw = Vec::with_capacity(payload_length);

                    for i in 0..payload_length {
                        payload_raw.push(msg_buf[6 + i] ^ mask[i % 4]);
                    }

                    let payload = String::from_utf8(payload_raw).unwrap();
                    println!("{}", payload);

                    stream.write_all(&[129, 5, 72, 101, 108, 108, 111])?;
                }
            }

            Ok(())
        }
        _ => Ok(()),
    }
}
