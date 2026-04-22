#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <string>

// Simple HTTP response structure
struct HttpResponse {
    std::string data;
    long status_code;
    bool success;
};

#endif // HTTP_RESPONSE_H

