#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

static unsigned char rol8(unsigned char val, unsigned int n) {
    n &= 7;
    return (val << n) | (val >> (8 - n));
}

static unsigned char ror8(unsigned char val, unsigned int n) {
    n &= 7;
    return (val >> n) | (val << (8 - n));
}

int contains_only_printable(const unsigned char *buf, int size) {
    for (int i = 0; i < size; i++) {
        unsigned char c = buf[i];
        if (!(isprint(c) || c == '\n' || c == '\r' || c == '\t')) {
            return 0; // no imprimible permitido
        }
    }
    return 1;
}

int main() {
    FILE *in = fopen("flag.enc", "rb");
    if (!in) {
        printf("No se puede abrir el archivo cifrado.\n");
        return 1;
    }

    fseek(in, 0, SEEK_END);
    int size = ftell(in);
    fseek(in, 0, SEEK_SET);

    unsigned char *buf = malloc(size);
    if (!buf) {
        fclose(in);
        printf("Error al reservar memoria.\n");
        return 1;
    }

    fread(buf, 1, size, in);
    fclose(in);

    unsigned int start, end;
    printf("Introduce semilla inicial (start): ");
    if (scanf("%u", &start) != 1) {
        printf("Error al leer start.\n");
        free(buf);
        return 1;
    }
    printf("Introduce semilla final (end): ");
    if (scanf("%u", &end) != 1) {
        printf("Error al leer end.\n");
        free(buf);
        return 1;
    }

    unsigned char *temp_buf = malloc(size);
    if (!temp_buf) {
        printf("Error al reservar memoria para buffer temporal.\n");
        free(buf);
        return 1;
    }

    const unsigned int report_interval = 1000000;
    time_t start_time = time(NULL);

    for (unsigned int seed = start; seed <= end; seed++) {
        memcpy(temp_buf, buf, size);

        srand(seed);

        for (int i = 0; i < size; i++) {
            unsigned int r1 = rand();
            unsigned int r2 = rand();
            rand();
            unsigned int r3 = rand();

            unsigned char x = temp_buf[i];
            x ^= (unsigned char)r3;
            x = ror8(x, r2 & 7);
            x ^= (unsigned char)r1;
            temp_buf[i] = x;
        }

        if (contains_only_printable(temp_buf, size)) {
            printf("---- Semilla: %u ----\n", seed);
            fwrite(temp_buf, 1, size, stdout);
            printf("\n\n");
        }

        if ((seed - start) % report_interval == 0) {
            time_t now = time(NULL);
            double elapsed = difftime(now, start_time);
            printf("[+] Semillas comprobadas: %u, tiempo transcurrido: %.0f segundos\n", seed - start + 1, elapsed);
        }
    }

    free(buf);
    free(temp_buf);

    printf("Proceso terminado.\n");
    return 0;
}
