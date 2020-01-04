#include <plisp/gc.h>
#include <plisp/object.h>
#include <plisp/read.h>
#include <plisp/write.h>
#include <plisp/compile.h>
#include <plisp/toplevel.h>
#include <plisp/builtin.h>
#include <stdio.h>
#include <assert.h>


int main(int argc, char *argv[]) {
    plisp_init_reader();
    plisp_init_compiler(argv[0]);
    plisp_init_toplevel();
    plisp_init_builtin();
    plisp_init_gc();

    if (argc > 1) {
        FILE *file = fopen(argv[1], "r");

        plisp_t obj;
        while (!plisp_c_eofp(obj = plisp_c_read(file))) {
            plisp_toplevel_eval(obj);
        }
    } else {
        while (1) {
            printf("> ");
            plisp_t obj = plisp_c_read(stdin);
            if (plisp_c_eofp(obj)) {
                putchar('\n');
                break;
            }
            plisp_c_write(stdout, plisp_toplevel_eval(obj));
            putchar('\n');
        }
    }

    plisp_end_compiler();

    return 0;
}
