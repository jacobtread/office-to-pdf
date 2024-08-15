# Office To PDF

> Converts office files to PDF files 

This library is a Rust wrapper around [unoserver](https://github.com/unoconv/unoserver) which uses [LibreOffice](https://www.libreoffice.org/) to
convert the office files to PDF.

Supports handling remote unoserver instances and load balancing traffic between multiple unoserver instances

> [!IMPORTANT]
> Only supported on Linux targets

## Installation

Install LibreOffice, Python 3, and Python 3 pip (Command for Debian, apt package manager. Adjust for your distro):

```sh
sudo apt-get install -y libreoffice python3 python3-pip
```

Install unoserver pip module

```sh
sudo pip install unoserver
```

`unoserver` must be on your path if you want to start a server 
`unoconvert` must be on your path if you want to convert files

Both should be on your path by default after installing unoserver.

## Start server instance

You can start `unoserver` using the following code:

```rust
use office_to_pdf::{start_unoserver, ConvertServer, ConvertLoadBalancer, ConvertServerHost};
use std::time::Duration;

// Create the server
let server = ConvertServer::new(ConvertServerHost::Local { port: 2003 });

// Check the server isn't already running
if server.is_running(ConvertServer::DEFAULT_RUNNING_TIMEOUT).await {
    
    // Start the server (The second port must be unique and not in use, its used by libreoffice)
    start_unoserver(2003, 2002).await.unwrap();
}
```

This server will be stopped when our program stops (Or earlier if you call `.abort()` on its handle) because of this its recommended if your using this as a long running server to instead run unoserver as a background OS service.

## Default server

The default example will use the default server port (2003)

```rust
use office_to_pdf::ConvertServer;

let input_bytes = &[/* YOUR INPUT BYTES */]
let output = ConvertServer::default()
    .convert_to_pdf(input_bytes)
    .await
    .unwrap();
```
> [!INFO]
> You must have the `unoserver` running at the same time for this to work.
>
> Or you can start one using the command above

## Custom local server port

You can specify a custom port for a local server using the following:

```rust
use office_to_pdf::{ConvertServer, ConvertServerHost};

let input_bytes = &[/* YOUR INPUT BYTES */]
let output = ConvertServer::new(ConvertServerHost::Local { port: 5000 })
    .convert_to_pdf(input_bytes)
    .await
    .unwrap();
```

## Remote unoserver

You can specify a remote server using the following:

```rust
use office_to_pdf::{ConvertServer, ConvertServerHost};

let input_bytes = &[/* YOUR INPUT BYTES */]
let output = ConvertServer::new(ConvertServerHost::Remote {
    host: "10.0.2.1".to_string(),
    port: 5000,
})
.convert_to_pdf(input_bytes)
.await
.unwrap();
```

## Load balancing

Converting larger files can block a `unoserver` for some period of time. You can run multiple `unoserver` instances and use a load balancer to distribute load amongst the various servers.

The servers will be checked to see if they are busy and the next free server will be used instead:

```rust
use office_to_pdf::{ConvertServer, ConvertLoadBalancer, ConvertServerHost};
use std::time::Duration;
use tokio::task::JoinSet;

let pool = ConvertLoadBalancer::new(
    // Available servers
    vec![
        ConvertServer::new(ConvertServerHost::Remote {
            host: "localhost".to_string(),
            port: 9250,
        }),
        ConvertServer::new(ConvertServerHost::Remote {
            host: "localhost".to_string(),
            port: 9251,
        }),
        ConvertServer::new(ConvertServerHost::Remote {
            host: "localhost".to_string(),
            port: 9252,
        }),
        ConvertServer::new(ConvertServerHost::Remote {
            host: "localhost".to_string(),
            port: 9253,
        }),
        ConvertServer::new(ConvertServerHost::Remote {
            host: "localhost".to_string(),
            port: 9254,
        }),
    ],
    // Maximum connect timeout
    Duration::from_millis(200),
    // Busy check timeout (Time allowed for a response before server is considered busy)
    Duration::from_millis(500),
);

let mut join_set = JoinSet::new();

// Sample test to spawn 50 conversions distributed amongst the servers
for _ in 0..50 {
    let pool = pool.clone();

    join_set.spawn(async move {
        let input_bytes = &[ /* YOUR INPUT BYTES */ ];
        pool.handle(input_bytes).await.unwrap();
    });
}

while (join_set.join_next().await).is_some() {}

```

## Checking convertable

You can check if a mime type is supported for conversion using the following:

```rust
use office_to_pdf::is_known_convertable;

let mime = "text/plain";
let is_convertable = is_known_convertable(mime);
```