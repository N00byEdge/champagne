// zig can't take va_args yet so we'll have to do this in C

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

typedef uint16_t WCHAR;

void c_log_impl(char const *function, char const *file, int line, WCHAR const *msg);
void c_panic_impl(char const *function, char const *file, int line, WCHAR const *msg) __attribute__((noreturn));
#define c_log(msg) c_log_impl(__FUNCTION__, __FILE__, __LINE__, msg);
#define c_panic(msg) c_panic_impl(__FUNCTION__, __FILE__, __LINE__, msg);

#define WRITE do { if(written == max) return written; } while(0)

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

    while(*format) {
        if(*format++ == '%') {
            switch(*format++) {
            case 's': {
                WCHAR const *str = va_arg(args, WCHAR const *);
                c_log(str);
                while(*str) {
                    WRITE;
                    *buffer++ = *str++;
                }
                break;
            }
            default:
                c_log(format-1);
                c_panic(u"Unknown format specifier!");
            }
        } else {
            WRITE;
            *buffer++ = *(format-1);
        }
    }

    if(written <= sizeOfBuffer - 1) buffer[written] = 0;

    return written;
}
