import socket

from config import BUFFER_SIZE, HOST, PORT
from http_parser import parse_request
from http_response import build_response
from router import handle_request


def create_bad_request_response(message: str) -> bytes:
    return build_response(
        status_code=400,
        headers={"Content-Type": "text/plain; charset=utf-8"},
        body=f"400 Bad Request\n{message}",
    )


def receive_http_request(client_socket: socket.socket) -> bytes:
    raw_data = b""

    while b"\r\n\r\n" not in raw_data:
        chunk = client_socket.recv(BUFFER_SIZE)
        if not chunk:
            break
        raw_data += chunk

    return raw_data


def start_server() -> None:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"HTTP server is listening on {HOST}:{PORT}")

    while True:
        client_socket, client_address = server_socket.accept()

        with client_socket:
            try:
                raw_request = receive_http_request(client_socket)
                request = parse_request(raw_request)
                print(f"[REQUEST] {client_address[0]} {request['method']} {request['target']}")
                response = handle_request(request)
            except ValueError as error:
                response = create_bad_request_response(str(error))
            except Exception as error:
                response = build_response(
                    status_code=500,
                    headers={"Content-Type": "text/plain; charset=utf-8"},
                    body=f"500 Internal Server Error\n{error}",
                )

            client_socket.sendall(response)


if __name__ == "__main__":
    start_server()
