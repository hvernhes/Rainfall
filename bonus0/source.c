#include <unistd.h>
#include <string.h>
#include <stdio.h>
 
void	p(char *dst, char *prompt)
{
	char	buf[4104];
	char	*newline;
 
	puts(prompt);
	read(0, buf, 0x1000);
	newline = strchr(buf, '\n');
	*newline = '\0';
	strncpy(dst, buf, 20);	// ⚠️ Pas de null-terminator si strlen(buf) >= 20
}
 
void	pp(char *dst)
{
	char	first[20];
	char	second[20];
 
	p(first, " - ");
	p(second, " - ");
	strcpy(dst, first);				// ⚠️ strlen déborde dans second si first pas null-terminé
	dst[strlen(dst)] = ' ';
	dst[strlen(dst)] = '\0';
	strcat(dst, second);			// ⚠️ 61 bytes au total dans dst[54] → overflow
}
 
int		main(void)
{
	char	buf[54];
 
	pp(buf);
	puts(buf);
	return (0);
}
 
