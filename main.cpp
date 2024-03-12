#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

// Function to handle incoming requests
void handle_request(tcp::socket* frontend_socket, std::string backend_host, std::string backend_port) {
    try {
        // Set up backend resolver and connect
        net::io_context io_context;
        tcp::resolver resolver(io_context);
        auto backend_endpoint = resolver.resolve(backend_host, backend_port);
        tcp::socket backend_socket(io_context);
        net::connect(backend_socket, backend_endpoint);

        // Read request from frontend
        beast::flat_buffer buffer;
        http::request<http::string_body> request;
        http::read(*frontend_socket, buffer, request);

        // Modify request if needed
        // e.g., update target host to backend host
        request.set(http::field::host, backend_host);

        // Send request to backend
        http::write(backend_socket, request);

        // Read response from backend
        beast::flat_buffer response_buffer;
        http::response<http::string_body> response;
        http::read(backend_socket, response_buffer, response);

        // Send response to frontend
        http::write(*frontend_socket, response);
    } catch (const std::exception& e) {
        std::cerr << "Error handling request: " << e.what() << std::endl;
    }
}

int main() {
    try {
        // Set up frontend acceptor
        net::io_context io_context;
        tcp::acceptor acceptor(io_context, {{}, 8080});
        std::cout << "Proxy server listening on port 8080..." << std::endl;

        tcp::socket server_socket(io_context), client_socket(io_context);

        acceptor.accept(client_socket);
        beast::flat_buffer buffer1;
        http::request<http::string_body> creq;
        http::read(client_socket, buffer1, creq);

        std::cout << "got a request containing: " << creq.body() << std::endl;

        tcp::endpoint server_endpoint(net::ip::address::from_string("127.0.0.1"), 8000);
        server_socket.connect(server_endpoint);

        http::request<http::empty_body> req(http::verb::get, "/", 11);
        req.set(http::field::host, "localhost");
        req.set(http::field::user_agent, "Boost Beast Client");
        http::write(server_socket, req);

        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(server_socket, buffer, res);

        http::write(client_socket, res);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}