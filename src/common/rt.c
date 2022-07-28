// zig can't take va_args yet so we'll have to do this in C

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

typedef uint16_t WCHAR;

void c_log_impl(char const *function, char const *file, int line, WCHAR const *msg);
void c_panic_impl(char const *function, char const *file, int line, WCHAR const *msg) __attribute__((noreturn));
#define c_log(msg) c_log_impl(__FUNCTION__, __FILE__, __LINE__, msg);
#define c_panic(msg) c_panic_impl(__FUNCTION__, __FILE__, __LINE__, msg);

#define WRITE do { if(written == max) return written; ++written; } while(0)

static int fill_buf_unsigned(
    WCHAR **buffer,
    size_t max,
    size_t written,
    unsigned long long v,
    int min_len,
    unsigned base,
    unsigned upper
) {
    unsigned curr = v % base;
    unsigned next = v / base;

    if(next || min_len > 0) {
        written = fill_buf_unsigned(buffer, max, written, next, min_len - 1, base, upper);
    }

    WRITE;
    *(*buffer)++ = (upper ? "0123456789ABCDEF" : "0123456789abcdef")[curr];
    return written;
}

int _vsnwprintf_s(
   WCHAR *buffer,
   size_t sizeOfBuffer,
   size_t count,
   WCHAR const *format,
   va_list args
) {
    size_t written = 0;
    size_t max = count < sizeOfBuffer - 1 ? count : sizeOfBuffer - 1;

    c_log(format);

    int min_len = 0;
    int upper = 1;
    int base = 10;

    while(*format) {
        if(*format++ == '%') { while(1) {
            switch(*format++) {
            case '0' ... '9':
                min_len *= 10;
                min_len += *(format - 1) - '0';
                continue;
            case 'i': {
                int i = va_arg(args, int);
                if(i < 0) {
                    WRITE;
                    *buffer++ = '-';
                    i = -i;
                }
                if(0) {
                case 'x':
                    upper = 0;
                case 'X':
                    base = 16;
                case 'u':
                    i = va_arg(args, unsigned);
                }
                written = fill_buf_unsigned(&buffer, max, written, i, min_len, base, upper);
                upper = 1;
                min_len = 0;
                base = 10;
                goto endfmt;
            }
            case 'c': {
                WCHAR w = va_arg(args, int);
                *buffer++ = w;
                goto endfmt;
            }
            case 'w': if(*format++ != 's') c_panic(u"non-s w fmt prefix");
            case 's': {
                WCHAR const *str = va_arg(args, WCHAR const *);
                c_log(str);
                while(*str) {
                    WRITE;
                    *buffer++ = *str++;
                }
                goto endfmt;
            }
            default:
                c_log(format-1);
                c_panic(u"Unknown format specifier!");
            }
        } endfmt:; } else {
            WRITE;
            *buffer++ = *(format-1);
        }
    }

    if(written <= sizeOfBuffer - 1) buffer[written] = 0;

    return written;
}
