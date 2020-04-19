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
	const void * pde;
	struct dark_energy * de;
	const char * args = "what the fuck";

	pde = darken_find(DARKEN_SYMBOL, DARKEN_IDX_TEMPLATE);
	if (pde == NULL)
		exit(90);
	de = darken_run(pde, args, (int) strlen(args), DARKEN_OUTPUT);
	if (de == NULL)
		exit(91);
	if (de->de_out != NULL && de->de_len > 0) {
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

