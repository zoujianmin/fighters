/*
 * Created by xiaoqzye@qq.com
 *
 * dark-energy template
 *
 * 2020/04/19
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <dark_energy.h>
#include DARKEN_HEADER

extern const unsigned char DARKEN_SYMBOL[];

int main(int argc, char *argv[])
{
	int rlen;
	const void * pde;
	struct dark_energy * de;
	const char * args = "what the fuck";

	rlen = 0;
	pde = darken_find(DARKEN_SYMBOL, DARKEN_IDX_TEMPLATE);
	if (pde == NULL)
		exit(90);
	de = darken_run(pde, args, (int) strlen(args), DARKEN_OUTPUT);
	if (de == NULL)
		exit(91);
	darken_output(de, &rlen);
	if (darken_has_output(de)) {
		fprintf(stdout, "output from child process:\n%s",
			(const char *) de->de_out);
		fflush(stdout);
	}
	fprintf(stdout, "\nExit status of child process: %d\n",
		de->de_stat);
	fflush(stdout);
	darken_free(de, 1);
	return 0;
}

