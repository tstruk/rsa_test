#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

struct akcipher_testvec {
	unsigned char *pub_key_n;
	unsigned char *pub_key_e;
	unsigned char *sec_key_d;
	unsigned char *m;
	unsigned char *s;
	unsigned int pub_key_n_size;
	unsigned int pub_key_e_size;
	unsigned int sec_key_d_size;
	unsigned int m_size;
	unsigned int s_size;
};

static struct akcipher_testvec rsa_tv = {
	.pub_key_n =
	"\x00\xAA\x36\xAB\xCE\x88\xAC\xFD\xFF\x55\x52\x3C\x7F\xC4\x52\x3F"
	"\x90\xEF\xA0\x0D\xF3\x77\x4A\x25\x9F\x2E\x62\xB4\xC5\xD9\x9C\xB5"
	"\xAD\xB3\x00\xA0\x28\x5E\x53\x01\x93\x0E\x0C\x70\xFB\x68\x76\x93"
	"\x9C\xE6\x16\xCE\x62\x4A\x11\xE0\x08\x6D\x34\x1E\xBC\xAC\xA0\xA1"
	"\xF5",
	.pub_key_e = "\x11",
	.sec_key_d =
	"\x0A\x03\x37\x48\x62\x64\x87\x69\x5F\x5F\x30\xBC\x38\xB9\x8B\x44"
	"\xC2\xCD\x2D\xFF\x43\x40\x98\xCD\x20\xD8\xA1\x38\xD0\x90\xBF\x64"
	"\x79\x7C\x3F\xA7\xA2\xCD\xCB\x3C\xD1\xE0\xBD\xBA\x26\x54\xB4\xF9"
	"\xDF\x8E\x8A\xE5\x9D\x73\x3D\x9F\x33\xB3\x01\x62\x4A\xFD\x1D\x51",
	.m = "\x54\x85\x9b\x34\x2c\x49\xea\x2a",
	.pub_key_n_size = 65,
	.pub_key_e_size = 1,
	.sec_key_d_size = 64,
	.m_size = 8,
};

void dump(gcry_mpi_t n, char* name)
{
	printf("===================\n");
	printf("%s:\n", name);
	gcry_mpi_dump(n);
	printf("\n===================\n");
}

int main (int c, char **v)
{
	gcry_mpi_t n;
	gcry_mpi_t e;
	gcry_mpi_t d;
	gcry_mpi_t m;
	gcry_mpi_t s = gcry_mpi_new(0);
	gcry_mpi_t m2 = gcry_mpi_new(0);
	gcry_error_t err;

	if (!gcry_check_version(GCRYPT_VERSION)) {
		printf("libgcrypt version mismatch\n", stderr);
		exit (2);
	}

	if ((err = gcry_mpi_scan(&n, GCRYMPI_FMT_USG, rsa_tv.pub_key_n,
				rsa_tv.pub_key_n_size, NULL)) != GPG_ERR_NO_ERROR) {
		fprintf (stderr, "Scan n failure: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	dump(n, "n");

	if ((err = gcry_mpi_scan(&e, GCRYMPI_FMT_USG, rsa_tv.pub_key_e,
				rsa_tv.pub_key_e_size, NULL)) != GPG_ERR_NO_ERROR) {
		fprintf (stderr, "Scan e failure: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}

	dump(e, "e");
	if ((err = gcry_mpi_scan(&d, GCRYMPI_FMT_USG, rsa_tv.sec_key_d,
				rsa_tv.sec_key_d_size, NULL)) != GPG_ERR_NO_ERROR) {
		fprintf (stderr, "Scan d failure: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}

	dump(d, "d");
	if ((err = gcry_mpi_scan(&m, GCRYMPI_FMT_USG, rsa_tv.m,
				rsa_tv.m_size, NULL)) != GPG_ERR_NO_ERROR) {
		fprintf (stderr, "Scan m failure: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	dump(m, "m");

	/* encrypt m into s */
	gcry_mpi_powm(s, m, e, n);
	dump(s, "encrypted text");

	/* decrypt s into m2 */
	gcry_mpi_powm(m2, s, d, n);
	dump(m2, "decrypted text");

	/* compare m and m2 */
	if (gcry_mpi_cmp(m, m2)) {
		printf("Test failed\n");
	} else {
		printf("Test passed\n");
	}
	return 0;
}
