// multipart_form_data.h
#pragma once
#include <string>
#include <vector>
#include <map>
#include <stdexcept>

class MultipartFormData {
public:
    struct File {
        std::string filename;
        std::vector<unsigned char> data;
    };

    MultipartFormData(const std::vector<unsigned char>& body) {
        parse_multipart_data(body);
    }

    bool has_field(const std::string& name) const {
        return fields.find(name) != fields.end();
    }

    bool has_file(const std::string& name) const {
        return files.find(name) != files.end();
    }

    std::string get_field(const std::string& name) const {
        auto it = fields.find(name);
        if (it != fields.end()) {
            return it->second;
        }
        return "";
    }

    File get_file(const std::string& name) const {
        auto it = files.find(name);
        if (it != files.end()) {
            return it->second;
        }
        return File();
    }

private:
    std::map<std::string, std::string> fields;
    std::map<std::string, File> files;

    void parse_multipart_data(const std::vector<unsigned char>& body) {
        std::string data(body.begin(), body.end());
        size_t pos = data.find("\r\n");
        if (pos == std::string::npos) return;

        std::string boundary = data.substr(0, pos);
        pos += 2;  // Ìø¹ý\r\n

        while (pos < data.size()) {
            size_t header_start = data.find("Content-Disposition: form-data;", pos);
            if (header_start == std::string::npos) break;

            size_t name_start = data.find("name=\"", header_start) + 6;
            size_t name_end = data.find("\"", name_start);
            std::string name = data.substr(name_start, name_end - name_start);

            size_t filename_start = data.find("filename=\"", header_start);
            bool is_file = (filename_start != std::string::npos &&
                filename_start < data.find("\r\n\r\n", header_start));

            size_t content_start = data.find("\r\n\r\n", header_start) + 4;
            size_t content_end = data.find(boundary, content_start) - 2;

            if (is_file) {
                File file;
                file.filename = data.substr(
                    filename_start + 10,
                    data.find("\"", filename_start + 10) - (filename_start + 10)
                );
                file.data = std::vector<unsigned char>(
                    body.begin() + content_start,
                    body.begin() + content_end
                );
                files[name] = file;
            }
            else {
                fields[name] = data.substr(content_start, content_end - content_start);
            }

            pos = content_end + boundary.length() + 2;
        }
    }
};