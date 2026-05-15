#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int		main(int argc, char **argv)
{
	int		nb;
	char	buf[40];

	nb = atoi(argv[1]);

	if (nb > 9)			// ⚠️ Ne bloque pas les valeurs négatives
		return (1);

	memcpy(buf, argv[2], nb * 4);	// ⚠️ nb négatif × 4 → size_t énorme (overflow)

	if (nb == 0x574f4c46)			// Valeur magique "WOLF"
		execl("/bin/sh", "sh", NULL);

	return (0);
}
