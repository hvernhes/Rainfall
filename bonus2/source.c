#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int		lang = 0;

void	greetuser(char *str)
{
	char	buf[64];

	if (lang == 1)
		strncpy(buf, "Hyvää päivää ", 14);
	else if (lang == 2)
		strncpy(buf, "Goedemiddag! ", 13);
	else
		strncpy(buf, "Hello ", 6);

	strcat(buf, str);	// ⚠️ Pas de vérification de taille → overflow si str trop long
	puts(buf);
}

int		main(int argc, char **argv)
{
	char	buf[76];
	char	*env_lang;

	if (argc < 3)
		return (0);

	env_lang = getenv("LANG");
	if (env_lang != NULL)
	{
		if (strcmp(env_lang, "fi") == 0)
			lang = 1;
		else if (strcmp(env_lang, "nl") == 0)
			lang = 2;
	}

	memset(buf, 0, 76);
	strncpy(buf, argv[1], 40);		// Max 40 bytes de argv[1]
	strncpy(buf + 40, argv[2], 32);	// Max 32 bytes de argv[2]

	greetuser(buf);
	return (0);
}
