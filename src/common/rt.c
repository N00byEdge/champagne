// zig can't take va_args yet so we'll have to do this in C

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

typedef uint16_t WCHAR;

void c_log_impl(char const *function, char const *file, int line, WCHAR const *msg);
void c_panic_impl(char const *function, char const *file, int line, WCHAR const *msg);
#define c_log(msg) c_log_impl(__FUNCTION__, __FILE__, __LINE__, msg);
#define c_panic(msg) c_panic_impl(__FUNCTION__, __FILE__, __LINE__, msg);

// Technically wrong calling convention but it should be compatible for this one
// Where is __win64 for clang??
__vectorcall
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
		if(*format == '%') {
			++format;
			switch(*format) {
			default:
				c_log(format);
				c_panic(u"Unknown format specifier!");
			}
		} else {
			if(written < max) {
				*buffer++ = *format++;
			} else {
				--written;
			}
		}
	}

	return written;
}
