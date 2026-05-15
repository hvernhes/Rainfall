#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int		main(int argc, char **argv)
{
	char	buf[66];
	FILE	*fd;

	if (argc < 2)
		return (0);

	fd = fopen("/home/user/end/.pass", "r");
	fread(buf, 1, 66, fd);

	buf[atoi(argv[1])] = '\0';	// ⚠️ atoi("") = 0 → buf[0] = '\0'

	if (strcmp(buf, argv[1]) == 0)	// ⚠️ strcmp("", "") = 0 si argv[1] = ""
		execl("/bin/sh", "sh", NULL);

	puts(buf);
	fclose(fd);
	return (0);
}
