#include <stdio.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/time.h>
#include <ctype.h>
#include "lists.h"

#define BUFLEN 4096
#define PORT 8080
#define URL_MAX_LEN 255
#define TRUE 1
#define FALSE 0
const char* const HTTP_VERSION_STR = "HTTP/1.1";

void print_header(void*);

const char* const get_code_str(int code) {
	//--------------------
	//specific error codes
	if(code == 200) {
		return "OK";
	} else if(code == 404) {
		return "File Not Found";
	} else if(code == 301) {
		return "Moved Temporarily";
	} else if(code == 400) {
		return "Bad Request";
	} else if(code == 405) {
		return "Method Not Allowed";
	//-------------------
	//generic error codes
	} else if(code >= 600) {
		return "Unknown";
	} else if(code >= 500) {
		return "Server Error";
	} else if(code >= 400) {
		return "Client Error";
	} else if(code >= 300) {
		return "Redirect";
	} else if(code >= 200) {
		return "Success";
	} else if(code >= 100) {
		return "Information";
	} else {
		fprintf(stderr, "Error on status code %d\n", code);
		return "MASSIVE ERROR";
	}
}

char* generate_raw_response(int code, char* headers[][2], size_t num_headers, char* body) {
	const char* const code_str = get_code_str(code);
	if(code < 0 || code >= 600) {
		fprintf(stderr, "Code (%d) cannot be greater than 600 or less than 0.", code);
	}

	char code_buffer[4];
	snprintf(code_buffer, 4, "%d", code);

	size_t total_size = 0;
	total_size += strlen(HTTP_VERSION_STR) + 1 + strlen(code_buffer) + 1 + strlen(code_str) + 1; //first line
	size_t size_first_line = total_size;
	size_t header_size_array[num_headers];

	for(int i = 0; i < num_headers; i++) {
		size_t header_size = strlen(headers[i][0]) + 2 + strlen(headers[i][1]) + 1;
		header_size_array[i] = header_size;
		total_size += header_size;
	}
	size_t body_size = strlen(body);
	total_size += 1 + body_size + 1;

	char* result = malloc(total_size * sizeof(char));
	if(result == NULL) {
		perror("Can't allocate buffer for response.");
		exit(EXIT_FAILURE);
	}

	snprintf(result, (size_first_line+1) * sizeof(char), "%s %s %s\n", HTTP_VERSION_STR, code_buffer, code_str);
	size_t current_loc = size_first_line * sizeof(char);
	for(int i = 0; i < num_headers; i++) {
		snprintf(result + current_loc, (header_size_array[i]+1) * sizeof(char), "%s: %s\n", headers[i][0], headers[i][1]);
		current_loc += header_size_array[i] * sizeof(char);
	}

	snprintf(result + current_loc, 1 + body_size + 1, "\n%s", body);

	return result;
}

char* generate_text_response(int code, char* mimetype, char* response) {
	char* headers[3][2] = {{"Content-type", mimetype}, {"Server", "RussellServC"}, {"Connection", "close"}};
	return generate_raw_response(code, headers, 3, response);
}

char* generate_html_response(int code, char* response) {
	return generate_text_response(code, "text/html, charset=utf-8", response);
}

char* generate_plaintext_response(int code, char* response) {
	return generate_text_response(code, "text/plain, charset=utf-8", response);
}

char* generate_basic_response(char* response) {
	return generate_plaintext_response(200, response);
}

char* read_file_raw(char* filename, int nullterm, size_t* filesize) {
	FILE* file = fopen(filename, "r");
	if(!file) {
		perror("Unable to open file");
		exit(EXIT_FAILURE);
	}
	fseek(file, 0L, SEEK_END);
	size_t loc = ftell(file);
	*filesize = loc;
	rewind(file);
	char* ptr = malloc(sizeof(char) * (loc+(nullterm ? 1 : 0)));
	if(ptr == NULL) {
		perror("Unable to serve file");
		exit(EXIT_FAILURE);
	}
	fread(ptr, sizeof(char), loc, file);
	if(nullterm) ptr[loc] = 0; //null terminate string
	fclose(file);
	return ptr;
}

char* read_file(char* filename) {
	size_t filesize;
	return read_file_raw(filename, TRUE, &filesize);
}

char* serve_page(int code, char* filename) {
	char* ptr = read_file(filename);
	char* res = generate_html_response(200, ptr);
	free(ptr);
	return res;
}

void render_page(int socket, int code, char* filename, char* vars[][2], int num_vars) {
	char* start = generate_html_response(code, "");
	send(socket, start, strlen(start), 0);
	free(start);

	char* ptr = read_file(filename);
	size_t file_len = strlen(ptr);
	const size_t max_var_len = 50;
	char var[max_var_len];
	size_t var_ptr = 0;
	size_t last_successful_spot = 0;
	size_t i;
	//printf("got to start of loop\n");
	for(i = 0; i < file_len; i++) {
		if(ptr[i] == '$') {
			//printf("hit dollar\n");
			send(socket, ptr+last_successful_spot, i-last_successful_spot, 0);
			var_ptr = 0;
			i++;
			while(var_ptr < max_var_len-1 && i < file_len && ptr[i] != '$') {
				var[var_ptr] = ptr[i];
				i++;
				var_ptr++;
			}
			var[var_ptr] = 0;
			if(ptr[i] == '$') {
				int sent = FALSE;
				for(int o = 0; o < num_vars; o++) {
					//printf("Comparing '%s' to vars[%d][0] '%s'\n", var, o, vars[o][0]);
					if(strcmp(vars[o][0], var) == 0) {
						send(socket, vars[o][1], strlen(vars[o][1]), 0);
						sent = TRUE;
						break;
					}
				}
				if(!sent) send(socket, "ERR", 3, 0);
				last_successful_spot = i+1;
			} else {
				goto cleanup;
			}
		}
	}

	send(socket, last_successful_spot+ptr, i-last_successful_spot-1, 0);
	
	cleanup:
	//printf("cleanup\n");
	close(socket);
	free(ptr);
}

enum HTTP_method {
	M_GET,
	M_POST,
	M_PUT,
	M_UPDATE,
	M_DELETE,
	M_UNKNOWN
};

char* get_method_name(enum HTTP_method method) {
	switch(method) {
		case M_GET: return "GET";
		case M_POST: return "POST";
		case M_PUT: return "PUT";
		case M_UPDATE: return "UPDATE";
		case M_DELETE: return "DELETE";
		case M_UNKNOWN: return "UNKNOWN";
		default: return "???";
	}
}

struct header {
	char *name, *value;
};

struct header* create_header(char* name, char* value) {
	/*size_t nlen = strlen(name);
	size_t vlen = strlen(value);
	size_t len = nlen + vlen + 2;
	struct header* ret = malloc(sizeof(struct header));
	if(!ret) return NULL;
	ret->data = malloc(len);
	if(!ret->data) return NULL;
	ret->name = ret->data;
	strncpy(ret->name, name, nlen + 1);
	ret->value = ret->data + nlen + 1;
	strncpy(ret->value, value, vlen + 1);
	return ret;*/
	struct header* ret = malloc(sizeof(struct header));
	ret->name = name;
	ret->value = value;
	return ret;
}

void destroy_header(void* headerp) {
	struct header* header = (struct header*) headerp;
	free(header->name);
	free(header->value);
	//printf("Freeing\n");
	free(header);
}

struct HTTP_request {
	enum HTTP_method method;
	char url[URL_MAX_LEN];
	int invalid;
	char* body;
	struct ll_item* headers;
};

#define EXPECT_STRING_LENGTH 40
//reads a string of unknown length into a char pointer
char* read_string_until(char* str, char delim, size_t* to_inc) {
	size_t cur_len = EXPECT_STRING_LENGTH;
	char* ptr = malloc(cur_len * sizeof(char));
	if(ptr == NULL) return NULL;
	size_t i;
	for(i = 0; str[i] != delim && str[i] != 0; i++) {
		ptr[i] = str[i];
		if(i >= cur_len - 2) {
			cur_len *= 2;
			ptr = realloc(ptr, cur_len);
			if(ptr == NULL) return NULL;
		}
		(*to_inc)++;
	}
	ptr[i] = 0;
	return ptr;
}

struct HTTP_request parse_request(char* response) {
	size_t ptr = 0;
	while(response[ptr] == ' ') ptr++;

	struct HTTP_request res;
	res.invalid = TRUE;
	if(response[ptr] == 0) return res;

	const size_t max_count = 20;
	char method[max_count];
	for(int i = 0; i < max_count; i++) method[i] = 0;

	size_t counter = 0;
	while(response[ptr] != ' ' && response[ptr] != 0 && counter < max_count - 1) {
		method[counter] = response[ptr];
		counter++;
		ptr++;
	}
	method[counter] = 0;
	if(counter >= max_count) {
		res.method = M_UNKNOWN;
		while(response[ptr] != ' ' && response[ptr] != 0) ptr++;
	} else {
		if(strcmp(method, "GET") == 0) res.method = M_GET;
		else if(strcmp(method, "POST") == 0) res.method = M_POST;
		else if(strcmp(method, "PUT") == 0) res.method = M_PUT;
		else if(strcmp(method, "DELETE") == 0) res.method = M_DELETE;
		else if(strcmp(method, "UPDATE") == 0) res.method = M_UPDATE;
		else {
			fprintf(stderr, "Unknown method: %s\n", method);
			res.method = M_UNKNOWN;
		}
	}
	if(response[ptr] == 0) return res;

	while(response[ptr] == ' ') ptr++;
	if(response[ptr] == 0) return res;

	counter = 0;
	while(response[ptr] != ' ' && response[ptr] != 0 && counter < URL_MAX_LEN-1) {
		res.url[counter] = response[ptr];
		counter++;
		ptr++;
	}
	res.url[counter] = 0;
	if(response[ptr] == 0) return res;

	while(response[ptr] == ' ' && response[ptr] != 0) ptr++;

	if(response[ptr] == 0) return res;
	res.body = NULL;
	res.headers = NULL;

	if(strncmp(response + ptr, "HTTP/", 5) != 0) {
		printf("Non http request?\n");
		return res;
	}
	ptr += 5;
	if(strncmp(response + ptr, "1.0", 3) != 0 && strncmp(response + ptr, "1.1", 3) != 0) {
		printf("Non recognized HTTP version string.\n");
		return res;
	}
	ptr += 3;

//printf("-------------'%s'\n", response + ptr);

	while(response[ptr] == ' ' && response[ptr] != 0) ptr++;
	if(response[ptr] == 0) return res;

	if(response[ptr] != '\r' || response[ptr] == 0) return res;
	ptr++;
	if(response[ptr] != '\n' || response[ptr] == 0) return res;
	ptr++;
//	printf("WHOO-----------------------------------1231233\n");

	struct header* lead = NULL;
	struct ll_item* current = NULL;
	res.headers = NULL;
	res.invalid = FALSE;

	while(TRUE) {
		while((response[ptr] == ' ' || response[ptr] == '\t') && response[ptr] != 0) ptr++;
		if(response[ptr] == 0) return res;
		if(response[ptr] == '\r') {
			ptr++;
			if(response[ptr] != '\n') return res;
			ptr++;
			break;
		}

		char* name = read_string_until(response + ptr, ':', &ptr);
		if(response[ptr] != ':') {
			free(name);
			return res;
		}
		ptr++;
		while(response[ptr] == ' ' && response[ptr] != 0) ptr++;
		if(response[ptr] == 0) {
			free(name);
			return res;
		}
		char* value = read_string_until(response+ptr, '\r', &ptr);

		lead = create_header(name, value);
		struct ll_item* tmp = malloc(sizeof(struct ll_item));
		tmp->data = lead;
		tmp->next = NULL;
		if(res.headers == NULL) {
			res.headers = tmp;
		} else {
			current->next = tmp;
		}
		current = tmp;
		//print_header((void*)lead);
		//print_list(res.headers, print_header);

		while((response[ptr] == ' ' || response[ptr] == '\t') && response[ptr] != 0) ptr++;
		if(response[ptr] == 0) return res;
		if(response[ptr] != '\r') return res;
		ptr++;
		if(response[ptr] != '\n') return res;
		ptr++;
	}

	res.body = read_string_until(response+ptr, 0, &ptr);

	return res;
}

void urldecode2(char *dst, const char *src, int dstmax)
{
	char* dstorig = dst;
	char a, b;
	while (*src) {
		if ((*src == '%') &&
		    ((a = src[1]) && (b = src[2])) &&
		    (isxdigit(a) && isxdigit(b))) {
			if (a >= 'a')
				a -= 'a'-'A';
			if (a >= 'A')
				a -= ('A' - 10);
			else
				a -= '0';
			if (b >= 'a')
				b -= 'a'-'A';
			if (b >= 'A')
				b -= ('A' - 10);
			else
				b -= '0';
			*dst++ = 16*a+b;
			src+=3;
		} else if (*src == '+') {
			*dst++ = ' ';
			src++;
		} else {
			*dst++ = *src++;
		}
		if(dst - dstorig >= dstmax-1) {
			break;
			//printf("BREAKING IT\n");
		}
	}
	*dst = '\0';
	printf("End: '%s'\n", dstorig);
}

#define FORM_NAME_MAX 128
#define FORM_VAL_MAX 1024
/*char* decode_form_data(char* data) {
	char name[FORM_NAME_MAX] = {0};
	char val[FORM_VAL_MAX] = {0};
	size_t datalen = strlen(data);
	int reading_name = TRUE;
	int counter = 0;

	for(size_t i = 0; i < datalen; i++) {
		if(reading_name) {
			if(data[i] == '=') {
				reading_name = FALSE;
				name[counter] = 0;
				i++;
				counter = 0;
			} else {
				if(counter >= FORM_NAME_MAX -1) {
					return NULL;
				}
				name[counter] = data[i];
				counter++;
			}
		} else {
			if(data[i] == '&') {
				reading_name = TRUE;
				val[counter] = 0;
				i++;
				counter = 0;
			} else {
				if(counter >= FORM_VAL_MAX -1) {
					return NULL;
				}
				val[counter] = data[i];
				counter++;
			}
		}
	}
}*/
char* read_post_name(char** ptr) {
	char* original = *ptr;
	char* val = *ptr;
	while(*val != '=') {
		//printf("%c\n", *val);
		if(*val == 0) return NULL;
		val++;
	}
	*val = 0;
	*ptr = val+1;
	return original;
}
char* read_post_val_alloc(char** ptr) {
	char* original = *ptr;
	char* val = *ptr;
	while(*val != '&') {
		if(*val == 0) break;
		val++;
	}
	*val = 0;
	*ptr = val+1;
	printf("original: %s\n", original);
	size_t len = strlen(original)+1;
	char* data = malloc(len * sizeof(char));
	urldecode2(data, original, len);
	return data;
}

void print_header(void* headerp) {
	struct header* header = (struct header*)headerp;
	printf("Header: '%s' -> '%s'\n", header->name, header->value);
}

char* stringcat(char* string1, char* string2) {
	size_t s1 = strlen(string1);
	size_t s2 = strlen(string2);
	char* res = malloc(s1 + s2 + 1);
	if(res == NULL) return NULL;
	strncpy(res, string1, s1);
	strncpy(res + s1, string2, s2);
	res[s1 + s2] = 0;
	return res;
}

char* mstringcat(int num, ...) {
	va_list args;
	va_start(args, num);

	size_t sizes[num];
	char* chars[num];
	size_t total = 0;
	for(int i = 0; i < num; i++) {
		char* val = va_arg(args, char*);
		chars[i] = val;
		sizes[i] = strlen(val);
		total += sizes[i];
	}

	char* res = malloc(total + 1);
	if(res == NULL) {
		va_end(args);
		return NULL;
	}
	char* ptr = res;
	for(int i = 0; i < num; i++) {
		strncpy(ptr, chars[i], sizes[i]);
		ptr += sizes[i];
	}
	*ptr = 0;

	va_end(args);
	return res;
}

int main(int argc, char const *argv[]) {
	struct timeval start, stop;
	int server_fd, new_socket, valread;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char buffer[BUFLEN] = {0};

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons( PORT );

	// Forcefully attaching socket to the port 8080
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(server_fd, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	while(1) {
		if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
			perror("accept");
			exit(EXIT_FAILURE);
		}
		valread = read(new_socket, buffer, BUFLEN-1);
		printf("Read %d bytes.\n", valread);
		//printf("%s\n---------------------\n", buffer);
		buffer[valread] = 0;
		printf("%s\n", buffer);

		gettimeofday(&start, 0);
		struct HTTP_request request = parse_request(buffer);
		if(request.invalid) {
			printf("Received failed request: %s\n", buffer);
			fprintf(stderr, "Invalid request.\n");
			char* result = generate_plaintext_response(400, "Bad request");
			send(new_socket, result, strlen(result), 0);
			free(result);
			close(new_socket);
			continue;
		}// else if(request.headers != NULL) {
		//	print_list(request.headers, print_header);
		//}
		// else if(request.body != NULL) {printf("%s\n", request.body);}

		printf("%s %s\n", get_method_name(request.method), request.url);
		char* result = NULL;
		if(strcmp(request.url, "/") == 0) {
			if(request.method == M_GET) {
				result = serve_page(200, "index.html");
			} else if(request.method == M_POST) {
				/*char* vars[2][2] = {
					{"ERRORCODE", "405"},
					{"ERROR", "Method not allowed."}
				};
				render_page(new_socket, 405, "error.html", vars, 2);
				goto time;
				continue;*/
				//result = generate_plaintext_response(200, buffer);

				char* qptr = request.body;
				/*for(int i = 3; i < valread; i++) {
					if(buffer[i] == '\n' && buffer[i-1] == '\r' && buffer[i-2] == '\n' && buffer[i-3] == '\r') {
						qptr = buffer + i+1;
						break;
					}
				}*/

				size_t qptrlen = strlen(qptr);
				char* alex = malloc((qptrlen+1) * sizeof(char));
				char* alex_orig = alex;
				char* writtendata = "No data! Is your request too big?";
				int founddata = FALSE;
				strncpy(alex, qptr, qptrlen);
				alex[qptrlen] = 0;
				while(TRUE) {
					char* carter = read_post_name(&alex);
					if(carter == NULL) break;
					printf("NAME: %s\n", carter);
					char* data = read_post_val_alloc(&alex);
					if(data == NULL) break;
					printf("VAL: %s\n", data);
					if(strcmp(carter, "text") == 0 && !founddata) {
						writtendata = data;
						printf("to be writtendata: %s\n", writtendata);
						founddata = TRUE;
					} else {
						free(data);
					}
				}
				char* vars[3][2] = {{"QUERY", qptr}, {"REQUEST", buffer}, {"DATA", writtendata}};
				render_page(new_socket, 200, "post.html", vars, 3);
				printf("written data: %s\n", writtendata);
				if(founddata) free(writtendata);
				free(alex_orig);
				goto time;
				continue;
			} else {
				char* vars[2][2] = {{"ERRORCODE", "405"}, {"ERROR", "Method not allowed!"}};
				render_page(new_socket, 405, "error.html", vars, 2);
				goto time;
				continue;
			}
		} else if(request.method == M_GET && strncmp(request.url, "/page/", 6) == 0) {
			char* vars[2][2] = {{"PAGE", request.url+6}};
			render_page(new_socket, 200, "page.html", vars, 1);
			goto time;
			continue;
		} else if(strcmp(request.url, "/login") == 0) {
			if(request.method == M_GET) {
				result = serve_page(200, "login.html");
			} else if(request.method == M_POST) {
				char* body = malloc(strlen(request.body)+1);
				char* body_orig = body;
				strcpy(body, request.body);

				char* user = NULL;
				char* pass = NULL;
				while(TRUE) {
					char* carter = read_post_name(&body);
					if(carter == NULL) break;
					char* data = read_post_val_alloc(&body);
					if(data == NULL) break;
					if(strcmp(carter, "user") == 0 && user == NULL) {
						user = data;
					} else if(strcmp(carter, "pass") == 0 && pass == NULL) {
						pass = data;
					} else {
						free(data);
					}
				}

				if(user != NULL && pass != NULL) {
					char* cookie1 = stringcat("username=", user);
					char* cookie2 = stringcat("password=", pass);
					char* headers[5][2] = {{"Content-type", "text/plain, charset=utf-8"}, {"Server", "RussellServC"}, {"Connection", "close"}, {"Set-Cookie", cookie1}, {"Set-Cookie", cookie2}};
					result = generate_raw_response(200, headers, 5, "Logged in!");
					free(cookie1);
					free(cookie2);
				} else {
					result = generate_plaintext_response(400, "No username/password specified.");
				}

				if(user != NULL) free(user);
				if(pass != NULL) free(pass);
				free(body_orig);
			} else {
				char* vars[2][2] = {{"ERRORCODE", "405"}, {"ERROR", "Method not allowed!"}};
				render_page(new_socket, 405, "error.html", vars, 2);
				goto time;
				continue;
			}
		} else if(request.method == M_GET && strcmp(request.url, "/account") == 0) {
			struct ll_item* val = request.headers;
			char* data = NULL;
			while(val) {
				struct header* header = val->data;
				if(strcasecmp(header->name, "Cookie") == 0) {
					data = header->value;
					break;
				}
				val = val->next;
			}
			if(data == NULL) {
				result = generate_plaintext_response(200, "Not logged in!");
			} else {
				/*char* user = NULL;
				char* pass = NULL;
				size_t max = strlen(data);
				char* ptr = malloc(max + 1);
				strcpy(ptr, data);
				size_t index = 0;
				while(TRUE) {
					char* str = read_string_until(ptr + index, '=', &index);
					if(str == NULL) {
						result = generate_plaintext_response(200, "error");
						goto end_account;
					}
					index++;
					if(strcmp(str, "username") == 0 && user == NULL) {
						user = read_string_until(ptr + index, ';', &index);
						if(index >= max-1) goto
					}
					else if(strcmp(str, "password") == 0 && pass == NULL) pass = str;
					else free(str);
				}

				end_account:
				free(ptr);*/
				char* vars[1][2] = {{"DATA", data}};
				render_page(new_socket, 200, "account.html", vars, 1);
				goto time;
				continue;
			}
		} else if(request.method == M_GET && strcmp(request.url, "/plaintext") == 0) {
			result = generate_plaintext_response(200, "Here's some plaintext!");
		} else if(request.method == M_GET && strcmp(request.url, "/useragent") == 0) {
			struct ll_item* val = request.headers;
			char* data = NULL;
			while(val) {
				struct header* header = val->data;
				if(strcasecmp(header->name, "User-Agent") == 0) {
					data = header->value;
					break;
				}
				val = val->next;
			}
			if(data == NULL) {
				result = generate_plaintext_response(200, "No user agent header!");
			} else {
				char* browsertype = "NO IDEA";
				if(strstr(data, "Firefox") != NULL) browsertype = "Firefox";
				else if(strstr(data, "Chrome") != NULL) browsertype = "Chrome";
				else if(strstr(data, "Chromium") != NULL) browsertype = "Chromium";
				else if(strstr(data, "Safari") != NULL) browsertype = "Safari";
				else if(strstr(data, "Opera") != NULL) browsertype = "Opera";
				else if(strstr(data, "MSIE") != NULL) browsertype = "Internet Explorer";

				char* res = generate_plaintext_response(200, "Your user agent is: ");
				result = mstringcat(4, res, data, "\nI'd guess your browser is: ", browsertype);
				free(res);
			}
		} else if(request.method == M_GET && strcmp(request.url, "/a.png") == 0) {
			result = generate_text_response(200, "image/png", "");
			send(new_socket, result, strlen(result), 0);
			free(result);
			size_t filesize;
			result = read_file_raw("a.png", FALSE, &filesize);
			send(new_socket, result, filesize, 0);
			free(result);
			close(new_socket);
			goto time;
			continue;
		} else if(request.method == M_GET && strcmp(request.url, "/favicon.ico") == 0) {
			result = generate_text_response(200, "image/x-icon", "");
			send(new_socket, result, strlen(result), 0);
			free(result);
			size_t filesize;
			result = read_file_raw("favicon.ico", FALSE, &filesize);
			send(new_socket, result, filesize, 0);
			free(result);
			close(new_socket);
			goto time;
			continue;
		} else if(request.method == M_GET && strncmp(request.url, "/bee.bmp", 8) == 0) {
			size_t urllen = sizeof(request.url);
			size_t loc = 0;
			for(size_t i = 0; i < urllen; i++) {
				if(request.url[i] == '?') {
					loc = i;
					break;
				}
			}
			long int skip = -1;
			long int offset = 0;
			long int val = 0;
			if(loc != 0) {
				char* ptr = request.url + loc + 1;
				while(TRUE) {
					char* name = read_post_name(&ptr);
					if(name != NULL) {
				    		char* nextptr = read_post_val_alloc(&ptr);
				    		if(nextptr != NULL) {
							if(strcmp(name, "pts") == 0) {
								skip = strtol(nextptr, (char **)NULL, 10);
							} else if(strcmp(name, "offset") == 0) {
								offset = strtol(nextptr, (char**)NULL, 10);
							} else if(strcmp(name, "val") == 0) {
								val = (char)strtol(nextptr, (char**)NULL, 10);
							}
				    			free(nextptr);
						} else {
							break;
						}
					} else {
						break;
					}
				}
			}
			printf("Skip: %ld\n", skip);
			result = generate_text_response(200, "image/bmp", "");
			send(new_socket, result, strlen(result), 0);
			free(result);
			size_t filesize;
			result = read_file_raw("bee.bmp", FALSE, &filesize);
			if(offset < 0) offset = 0;
			if(skip > 0) for(int i = 54 + offset; i < filesize; i+=skip) result[i] = val;
			printf("bee file size: %zu\n", filesize);
			send(new_socket, result, filesize, 0);
			free(result);
			close(new_socket);
			goto time;
			continue;
		} else if(request.method == M_GET && strcmp(request.url, "/form") == 0) {
			result = generate_html_response(200, "<form action=\"/\" method=\"post\"><input type=\"submit\" value=\"Submit\" name=\"submit\" /></form>");
		} else if(request.method == M_GET && strcmp(request.url, "/bee") == 0) {
			result = serve_page(200, "bee.html");
		} else {
			//result = generate_plaintext_response(404, "Hmm... I can't find that URL.");
			char* vars[2][2] = {
				{"ERRORCODE", "404"},
				{"ERROR", "File not found!"}
			};
			render_page(new_socket, 404, "error.html", vars, 2);
			goto time;
			continue;
		}

		if(!result) {
			fprintf(stderr, "Result not set during loop.");
			exit(EXIT_FAILURE);
		}
		send(new_socket, result, strlen(result), 0);
		free(result);
		close(new_socket);

		time:
		if(!request.invalid) {
			if(request.body != NULL) free(request.body);
			if(request.headers != NULL) free_list(request.headers, destroy_header);
		}
		gettimeofday(&stop, 0);
		if(stop.tv_sec != start.tv_sec)
			printf("Took %ldsec and also ", stop.tv_sec - start.tv_sec);
		printf("Took %dus.\n", stop.tv_usec - start.tv_usec);
	}

	return 0;
}
