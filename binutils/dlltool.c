#define show_allnames 0

/* dlltool.c -- tool to generate stuff for PE style DLLs 
   Copyright (C) 1995 Free Software Foundation, Inc.

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */


/*
   This program allows you to build the files necessary to create
   DLLs to run on a system which understands PE format image files.
   (eg, Windows NT)

   A DLL contains an export table which contains the information
   which the runtime loader needs to tie up references from a
   referencing program. 

   The export table is generated by this program by reading
   in a .DEF file or scanning the .a and .o files which will be in the
   DLL.  A .o file can contain information in special  ".drectve" sections
   with export information.  

   A DEF file contains any number of the following commands:


   NAME <name> [ , <base> ] 
   The result is going to be <name>.EXE

   LIBRARY <name> [ , <base> ]    
   The result is going to be <name>.DLL

   EXPORTS  ( <name1> [ = <name2> ] [ @ <integer> ] [ NONAME ] [CONSTANT] ) *
   Declares name1 as an exported symbol from the
   DLL, with optional ordinal number <integer>

   IMPORTS  ( [ <name> = ] <name> . <name> ) *
   Ignored for compatibility

   DESCRIPTION <string>
   Puts <string> into output .exp file in the .rdata section

   [STACKSIZE|HEAPSIZE] <number-reserve> [ , <number-commit> ]
   Generates --stack|--heap <number-reserve>,<number-commit>
   in the output .drectve section.  The linker will
   see this and act upon it.

   [CODE|DATA] <attr>+
   SECTIONS ( <sectionname> <attr>+ )*
   <attr> = READ | WRITE | EXECUTE | SHARED
   Generates --attr <sectionname> <attr> in the output
   .drectve section.  The linker will see this and act
   upon it.


   A -export:<name> in a .drectve section in an input .o or .a
   file to this program is equivalent to a EXPORTS <name>
   in a .DEF file.



   The program generates output files with the prefix supplied
   on the command line, or in the def file, or taken from the first 
   supplied argument.

   The .exp.s file contains the information necessary to export
   the routines in the DLL.  The .lib.s file contains the information
   necessary to use the DLL's routines from a referencing program.



   Example:

   file1.c: 
   asm (".section .drectve");  
   asm (".ascii \"-export:adef\"");

   adef(char *s)
   {
   printf("hello from the dll %s\n",s);
   }

   bdef(char *s)
   {
   printf("hello from the dll and the other entry point %s\n",s);
   }

   file2.c:
   asm (".section .drectve");
   asm (".ascii \"-export:cdef\"");
   asm (".ascii \"-export:ddef\"");
   cdef(char *s)
   {
   printf("hello from the dll %s\n",s);
   }

   ddef(char *s)
   {
   printf("hello from the dll and the other entry point %s\n",s);
   }

   printf()
   {
   return 9;
   }

   main.c

   main()
   {
   cdef();
   }

   thedll.def

   LIBRARY thedll
   HEAPSIZE 0x40000, 0x2000
   EXPORTS bdef @ 20
   cdef @ 30 NONAME 

   SECTIONS donkey READ WRITE
   aardvark EXECUTE


   # compile up the parts of the dll

   gcc -c file1.c       
   gcc -c file2.c

   # put them in a library (you don't have to, you
   # could name all the .os on the dlltool line)

   ar  qcv thedll.in file1.o file2.o
   ranlib thedll.in

   # run this tool over the library and the def file
   ./dlltool --def thedll.def --output-exp thedll.o --output-lib thedll.a

   # build the dll with the library with file1.o, file2.o and the export table
   ld -o thedll.dll thedll.o thedll.in

   # build the mainline
   gcc -c themain.c 

   # link the executable with the import library
   ld -e main -Tthemain.ld -o themain.exe themain.o thedll.a

 */

#define PAGE_SIZE 4096
#define PAGE_MASK (-PAGE_SIZE)
#include "bfd.h"
#include "libiberty.h"
#include "bucomm.h"
#include "getopt.h"
#include <sys/types.h>
#include "demangle.h"

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#else
#ifndef WIFEXITED
#define WIFEXITED(w)	(((w)&0377) == 0)
#endif
#ifndef WIFSIGNALED
#define WIFSIGNALED(w)	(((w)&0377) != 0177 && ((w)&~0377) == 0)
#endif
#ifndef WTERMSIG
#define WTERMSIG(w)	((w) & 0177)
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(w)	(((w) >> 8) & 0377)
#endif
#endif


char *ar_name = "ar";
char *as_name = "as";
char *ranlib_name = "ranlib";

char *exp_name;
char *imp_name;
char *imp_name_lab;
char *dll_name;

int add_indirect = 0;
int add_underscore = 0;
int dontdeltemps = 0;

int yydebug;
char *def_file;

char *program_name;
char *strrchr ();
char *strdup ();

static int machine;
int killat;
static int verbose;
FILE *output_def;
FILE *base_file;
#ifdef DLLTOOL_ARM
static char *mname = "arm";
#endif

#ifdef DLLTOOL_I386
static char *mname = "i386";
#endif
#define PATHMAX 250		/* What's the right name for this ? */

char outfile[PATHMAX];
struct mac
  {
    char *type;
    char *how_byte;
    char *how_short;
    char *how_long;
    char *how_asciz;
    char *how_comment;
    char *how_jump;
    char *how_global;
    char *how_space;
    char *how_align_short;
    char *how_align_long;
  }
mtable[]
=
{
  {
#define MARM 0
    "arm", ".byte", ".short", ".long", ".asciz", "@", "ldr\tip,[pc]\n\tldr\tpc,[ip]\n\t.long", ".global", ".space", ".align\t2",".align\t4",
  }
  ,
  {
#define M386 1
    "i386", ".byte", ".short", ".long", ".asciz", "#", "jmp *", ".global", ".space", ".align\t2",".align\t4"
  }
  ,
    0
};


char *
rvaafter (machine)
     int machine;
{
  switch (machine)
    {
    case MARM:
      return "";
    case M386:
      return "";
    }
}

char *
rvabefore (machine)
     int machine;
{
  switch (machine)
    {
    case MARM:
      return ".rva\t";
    case M386:
      return ".rva\t";
    }
}

char *
asm_prefix (machine)
{
  switch (machine)
    {
    case MARM:
      return "";
    case M386:
      return "_";
    }
}
#define ASM_BYTE 	mtable[machine].how_byte
#define ASM_SHORT 	mtable[machine].how_short
#define ASM_LONG	mtable[machine].how_long
#define ASM_TEXT	mtable[machine].how_asciz
#define ASM_C 		mtable[machine].how_comment
#define ASM_JUMP 	mtable[machine].how_jump
#define ASM_GLOBAL	mtable[machine].how_global
#define ASM_SPACE	mtable[machine].how_space
#define ASM_ALIGN_SHORT mtable[machine].how_align_short
#define ASM_RVA_BEFORE 	rvabefore(machine)
#define ASM_RVA_AFTER  	rvaafter(machine)
#define ASM_PREFIX	asm_prefix(machine)
#define ASM_ALIGN_LONG mtable[machine].how_align_long
static char **oav;


FILE *yyin;			/* communications with flex */
extern int linenumber;
void
process_def_file (name)
     char *name;
{
  FILE *f = fopen (name, "r");
  if (!f)
    {
      fprintf (stderr, "%s: Can't open def file %s\n", program_name, name);
      exit (1);
    }

  yyin = f;

  yyparse ();
}

/**********************************************************************/

/* Communications with the parser */


typedef struct dlist
{
  char *text;
  struct dlist *next;
}
dlist_type;

typedef struct export
  {
    char *name;
    char *internal_name;
    int ordinal;
    int constant;
    int noname;
    int hint;
    struct export *next;
  }
export_type;

static char *d_name;		/* Arg to NAME or LIBRARY */
static int d_nfuncs;		/* Number of functions exported */
static int d_named_nfuncs;	/* Number of named functions exported */
static int d_low_ord;		/* Lowest ordinal index */
static int d_high_ord;		/* Highest ordinal index */
static export_type *d_exports;	/*list of exported functions */
static export_type **d_exports_lexically;	/* vector of exported functions in alpha order */
static dlist_type *d_list;	/* Descriptions */
static dlist_type *a_list;	/* Stuff to go in directives */

static int d_is_dll;
static int d_is_exe;

yyerror ()
{
  fprintf (stderr, "%s: Syntax error in def file %s:%d\n",
	   program_name, def_file, linenumber);
}

void
def_exports (name, internal_name, ordinal, noname, constant)
     char *name;
     char *internal_name;
     int ordinal;
     int noname;
     int constant;
{
  struct export *p = (struct export *) xmalloc (sizeof (*p));

  p->name = name;
  p->internal_name = internal_name ? internal_name : name;
  p->ordinal = ordinal;
  p->constant = constant;
  p->noname = noname;
  p->next = d_exports;
  d_exports = p;
  d_nfuncs++;
}


void
def_name (name, base)
     char *name;
     int base;
{
  if (verbose)
    fprintf (stderr, "%s NAME %s base %x\n", program_name, name, base);
  if (d_is_dll)
    {
      fprintf (stderr, "Can't have LIBRARY and NAME\n");
    }
  d_name = name;
  d_is_exe = 1;
}

void
def_library (name, base)
     char *name;
     int base;
{
  if (verbose)
    printf ("%s: LIBRARY %s base %x\n", program_name, name, base);
  if (d_is_exe)
    {
      fprintf (stderr, "%s: Can't have LIBRARY and NAME\n", program_name);
    }
  d_name = name;
  d_is_dll = 1;
}

void
def_description (desc)
     char *desc;
{
  dlist_type *d = (dlist_type *) xmalloc (sizeof (dlist_type));
  d->text = strdup (desc);
  d->next = d_list;
  d_list = d;
}

void
new_directive (dir)
     char *dir;
{
  dlist_type *d = (dlist_type *) xmalloc (sizeof (dlist_type));
  d->text = strdup (dir);
  d->next = a_list;
  a_list = d;
}

void
def_stacksize (reserve, commit)
     int reserve;
     int commit;
{
  char b[200];
  if (commit > 0)
    sprintf (b, "-stack 0x%x,0x%x ", reserve, commit);
  else
    sprintf (b, "-stack 0x%x ", reserve);
  new_directive (strdup (b));
}

void
def_heapsize (reserve, commit)
     int reserve;
     int commit;
{
  char b[200];
  if (commit > 0)
    sprintf (b, "-heap 0x%x,0x%x ", reserve, commit);
  else
    sprintf (b, "-heap 0x%x ", reserve);
  new_directive (strdup (b));
}


void
def_import (internal, module, entry)
     char *internal;
     char *module;
     char *entry;
{
  if (verbose)
    fprintf (stderr, "%s: IMPORTS are ignored", program_name);
}

void
def_version (major, minor)
{
  printf ("VERSION %d.%d\n", major, minor);
}


void
def_section (name, attr)
     char *name;
     int attr;
{
  char buf[200];
  char atts[5];
  char *d = atts;
  if (attr & 1)
    *d++ = 'R';

  if (attr & 2)
    *d++ = 'W';
  if (attr & 4)
    *d++ = 'X';
  if (attr & 8)
    *d++ = 'S';
  *d++ = 0;
  sprintf (buf, "-attr %s %s", name, atts);
  new_directive (strdup (buf));
}
void
def_code (attr)
     int attr;
{

  def_section ("CODE", attr);
}

void
def_data (attr)
     int attr;
{
  def_section ("DATA", attr);
}


/**********************************************************************/

void
run (what, args)
     char *what;
     char *args;
{
  char *s;
  int pid;
  int i;
  char **argv;
  extern char **environ;
  if (verbose)
    fprintf (stderr, "%s %s\n", what, args);

  /* Count the args */
  i = 0;
  for (s = args; *s; s++)
    if (*s == ' ')
      i++;
  i++;
  argv = alloca (sizeof (char *) * (i + 3));
  i = 0;
  argv[i++] = what;
  s = args;
  while (1)
    {
      argv[i++] = s;
      while (*s != ' ' && *s != 0)
	s++;
      if (*s == 0)
	break;
      *s++ = 0;
    }
  argv[i++] = 0;


  pid = vfork ();
  if (pid == 0)
    {
      execvp (what, argv);
      fprintf (stderr, "%s: can't exec %s\n", program_name, what);
      exit (1);
    }
  else if (pid == -1)
    {
      extern int errno;
      fprintf (stderr, "%s: vfork failed, %d\n", program_name, errno);
      exit (1);
    }
  else
    {
      int status;
      waitpid (pid, &status, 0);
      if (status)
	{
	  if (WIFSIGNALED (status))
	    {
	      fprintf (stderr, "%s: %s %s terminated with signal %d\n",
		       program_name, what, args, WTERMSIG (status));
	      exit (1);
	    }

	  if (WIFEXITED (status))
	    {
	      fprintf (stderr, "%s: %s %s terminated with exit status %d\n",
		       program_name, what, args, WEXITSTATUS (status));
	      exit (1);
	    }
	}
    }
}

/* read in and block out the base relocations */
static void
basenames (abfd)
     bfd *abfd;
{




}

void
scan_open_obj_file (abfd)
     bfd *abfd;
{
  /* Look for .drectve's */
  asection *s = bfd_get_section_by_name (abfd, ".drectve");
  if (s)
    {
      int size = bfd_get_section_size_before_reloc (s);
      char *buf = xmalloc (size);
      char *p;
      char *e;
      bfd_get_section_contents (abfd, s, buf, 0, size);
      if (verbose)
	fprintf (stderr, "%s: Sucking in info from %s\n",
		 program_name,
		 bfd_get_filename (abfd));

      /* Search for -export: strings */
      p = buf;
      e = buf + size;
      while (p < e)
	{
	  if (p[0] == '-'
	      && strncmp (p, "-export:", 8) == 0)
	    {
	      char *name;
	      char *c;
	      p += 8;
	      name = p;
	      while (*p != ' ' && *p != '-' && p < e)
		p++;
	      c = xmalloc (p - name + 1);
	      memcpy (c, name, p - name);
	      c[p - name] = 0;
	      def_exports (c, 0, -1, 0);
	    }
	  else
	    p++;
	}
      free (buf);
    }

  basenames (abfd);

  if (verbose)
    fprintf (stderr, "%s: Done readin\n",
	     program_name);

}


void
scan_obj_file (filename)
     char *filename;
{
  bfd *f = bfd_openr (filename, 0);

  if (!f)
    {
      fprintf (stderr, "%s: Unable to open object file %s\n",
	       program_name,
	       filename);
      exit (1);
    }
  if (bfd_check_format (f, bfd_archive))
    {
      bfd *arfile = bfd_openr_next_archived_file (f, 0);
      while (arfile)
	{
	  if (bfd_check_format (arfile, bfd_object))
	    scan_open_obj_file (arfile);
	  bfd_close (arfile);
	  arfile = bfd_openr_next_archived_file (f, arfile);
	}
    }

  if (bfd_check_format (f, bfd_object))
    {
      scan_open_obj_file (f);
    }

  bfd_close (f);
}

/**********************************************************************/


/* return the bit of the name before the last . */

static
char *
prefix (name)
     char *name;
{
  char *res = strdup (name);
  char *p = strrchr (res, '.');
  if (p)
    *p = 0;
  return res;
}

void
dump_def_info (f)
     FILE *f;
{
  int i;
  export_type *exp;
  fprintf (f, "%s ", ASM_C);
  for (i = 0; oav[i]; i++)
    fprintf (f, "%s ", oav[i]);
  fprintf (f, "\n");
  for (i = 0, exp = d_exports; exp; i++, exp = exp->next)
    {
      fprintf (f, "%s  %d = %s %s @ %d %s%s\n",
	       ASM_C,
	       i,
	       exp->name,
	       exp->internal_name,
	       exp->ordinal,
	       exp->noname ? "NONAME " : "",
	       exp->constant ? "CONSTANT" : "");
    }
}
/* Generate the .exp file */

int
sfunc (a, b)
     long *a;
     long *b;
{
  return *a - *b;
}



static void
flush_page (f, need, page_addr, on_page)
     FILE *f;
     long *need;
     long page_addr;
     int on_page;
{
  int i;

  /* Flush this page */
  fprintf (f, "\t%s\t0x%08x\t%s Starting RVA for chunk\n",
	   ASM_LONG,
	   page_addr,
	   ASM_C);
  fprintf (f, "\t%s\t0x%x\t%s Size of block\n",
	   ASM_LONG,
	   (on_page * 2) + (on_page & 1) * 2 + 8,
	   ASM_C);
  for (i = 0; i < on_page; i++)
    {
      fprintf (f, "\t%s\t0x%x\n", ASM_SHORT, need[i] - page_addr | 0x3000);
    }
  /* And padding */
  if (on_page & 1)
    fprintf (f, "\t%s\t0x%x\n", ASM_SHORT, 0 | 0x0000);

}


void
gen_def_file ()
{
  int i;
  export_type *exp;
  fprintf (output_def, ";");
  for (i = 0; oav[i]; i++)
    fprintf (output_def, " %s", oav[i]);

  fprintf (output_def, "\nEXPORTS\n");
  for (i = 0, exp = d_exports; exp; i++, exp = exp->next)
    {
      fprintf (output_def, "\t%s @ %d; %s\n",
	       exp->name,
	       exp->ordinal,
	       cplus_demangle (exp->internal_name, DMGL_ANSI | DMGL_PARAMS));
    }
}
void
gen_exp_file ()
{
  FILE *f;
  int i;
  export_type *exp;
  dlist_type *dl;
  int had_noname = 0;

  sprintf (outfile, "t%s", exp_name);

  if (verbose)
    fprintf (stderr, "%s: Generate exp file %s\n",
	     program_name, exp_name);

  f = fopen (outfile, "w");
  if (!f)
    {
      fprintf (stderr, "%s: Unable to open output file %s\n", program_name, outfile);
      exit (1);
    }
  if (verbose)
    {
      fprintf (stderr, "%s: Opened file %s\n",
	       program_name, outfile);
    }

  dump_def_info (f);
  if (d_exports)
    {
      fprintf (f, "\t.section	.edata\n\n");
      fprintf (f, "\t%s	0	%s Allways 0\n", ASM_LONG, ASM_C);
      fprintf (f, "\t%s	0	%s Time and date\n", ASM_LONG, ASM_C);
      fprintf (f, "\t%s	0	%s Major and Minor version\n", ASM_LONG, ASM_C);
      fprintf (f, "\t%sname%s	%s Ptr to name of dll\n", ASM_RVA_BEFORE, ASM_RVA_AFTER, ASM_C);
      fprintf (f, "\t%s	%d	%s Starting ordinal of exports\n", ASM_LONG, d_low_ord, ASM_C);


      fprintf (f, "\t%s	%d	%s Number of functions\n", ASM_LONG, d_high_ord - d_low_ord + 1, ASM_C);
      fprintf(f,"\t%s named funcs %d, low ord %d, high ord %d\n",
	      ASM_C,
	      d_named_nfuncs, d_low_ord, d_high_ord);
      fprintf (f, "\t%s	%d	%s Number of names\n", ASM_LONG,
	       show_allnames ? d_high_ord - d_low_ord + 1 : d_named_nfuncs, ASM_C);
      fprintf (f, "\t%safuncs%s  %s Address of functions\n", ASM_RVA_BEFORE, ASM_RVA_AFTER, ASM_C);

      fprintf (f, "\t%sanames%s	%s Address of Name Pointer Table\n", 
	       ASM_RVA_BEFORE, ASM_RVA_AFTER, ASM_C);

      fprintf (f, "\t%sanords%s	%s Address of ordinals\n", ASM_RVA_BEFORE, ASM_RVA_AFTER, ASM_C);

      fprintf (f, "name:	%s	\"%s\"\n", ASM_TEXT, dll_name);


      fprintf(f,"%s Export address Table\n", ASM_C);
      fprintf(f,"\t%s\n", ASM_ALIGN_LONG);
      fprintf (f, "afuncs:\n");
      i = d_low_ord;

      for (exp = d_exports; exp; exp = exp->next)
	{
	  if (exp->ordinal != i)
	    {
#if 0	      
	      fprintf (f, "\t%s\t%d\t%s %d..%d missing\n",
		       ASM_SPACE,
		       (exp->ordinal - i) * 4,
		       ASM_C,
		       i, exp->ordinal - 1);
	      i = exp->ordinal;
#endif
	      while (i < exp->ordinal)
		{
		  fprintf(f,"\t%s\t0\n", ASM_LONG);
		  i++;
		}
	    }
	  fprintf (f, "\t%s%s%s%s\t%s %d\n", ASM_RVA_BEFORE,
		   ASM_PREFIX,
		   exp->internal_name, ASM_RVA_AFTER, ASM_C, exp->ordinal);
	  i++;
	}

      fprintf (f,"%s Export Name Pointer Table\n", ASM_C);
      fprintf (f, "anames:\n");

      for (i = 0; exp = d_exports_lexically[i]; i++)
	{
	  if (!exp->noname || show_allnames)
	    fprintf (f, "\t%sn%d%s\n", ASM_RVA_BEFORE, exp->ordinal, ASM_RVA_AFTER);
	}

      fprintf (f,"%s Export Oridinal Table\n", ASM_C);
      fprintf (f, "anords:\n");
      for (i = 0; exp = d_exports_lexically[i]; i++)
	{
	  if (!exp->noname || show_allnames)
	    fprintf (f, "\t%s	%d\n", ASM_SHORT, exp->ordinal - d_low_ord);
	}

      fprintf(f,"%s Export Name Table\n", ASM_C);
      for (i = 0; exp = d_exports_lexically[i]; i++)
	if (!exp->noname || show_allnames)
	  fprintf (f, "n%d:	%s	\"%s\"\n", exp->ordinal, ASM_TEXT, exp->name);

      if (a_list)
	{
	  fprintf (f, "\t.section .drectve\n");
	  for (dl = a_list; dl; dl = dl->next)
	    {
	      fprintf (f, "\t%s\t\"%s\"\n", ASM_TEXT, dl->text);
	    }
	}
      if (d_list)
	{
	  fprintf (f, "\t.section .rdata\n");
	  for (dl = d_list; dl; dl = dl->next)
	    {
	      char *p;
	      int l;
	      /* We dont output as ascii 'cause there can
	         be quote characters in the string */

	      l = 0;
	      for (p = dl->text; *p; p++)
		{
		  if (l == 0)
		    fprintf (f, "\t%s\t", ASM_BYTE);
		  else
		    fprintf (f, ",");
		  fprintf (f, "%d", *p);
		  if (p[1] == 0)
		    {
		      fprintf (f, ",0\n");
		      break;
		    }
		  if (++l == 10)
		    {
		      fprintf (f, "\n");
		      l = 0;
		    }
		}
	    }
	}
    }


  /* Add to the output file a way of getting to the exported names
     without using the import library. */
  if (add_indirect)
    {
      fprintf (f, "\t.section\t.rdata\n");
      for (i = 0, exp = d_exports; exp; i++, exp = exp->next)
	if (!exp->noname || show_allnames)
	  {
	    fprintf (f, "\t%s\t__imp_%s\n", ASM_GLOBAL, exp->name);
	    fprintf (f, "__imp_%s:\n", exp->name);
	    fprintf (f, "\t%s\t%s\n", ASM_LONG, exp->name);
	  }
    }

  /* Dump the reloc section if a base file is provided */
  if (base_file)
    {
      int addr;
      long need[PAGE_SIZE];
      long page_addr;
      int numbytes;
      int num_entries;
      long *copy;
      int j;
      int on_page;
      fprintf (f, "\t.section\t.init\n");
      fprintf (f, "lab:\n");

      fseek (base_file, 0, SEEK_END);
      numbytes = ftell (base_file);
      fseek (base_file, 0, SEEK_SET);
      copy = malloc (numbytes);
      fread (copy, 1, numbytes, base_file);
      num_entries = numbytes / sizeof (long);


      fprintf (f, "\t.section\t.reloc\n");
      if (num_entries)
	{

	  int src;
	  int dst;
	  int last = -1;
	  qsort (copy, num_entries, sizeof (long), sfunc);
	  /* Delete duplcates */
	  for (src = 0; src < num_entries; src++)
	    {
	      if (last != copy[src]) 
		last = copy[dst++] = copy[src];
	    }
	  num_entries = dst;
	  addr = copy[0];
	  page_addr = addr & PAGE_MASK;		/* work out the page addr */
	  on_page = 0;
	  for (j = 0; j < num_entries; j++)
	    {
	      addr = copy[j];
	      if ((addr & PAGE_MASK) != page_addr)
		{
		  flush_page (f, need, page_addr, on_page);
		  on_page = 0;
		  page_addr = addr & PAGE_MASK;
		}
	      need[on_page++] = addr;
	    }
	  flush_page (f, need, page_addr, on_page);

	  fprintf (f, "\t%s\t0,0\t%s End\n", ASM_LONG, ASM_C);
	}
    }

  fclose (f);

  /* assemble the file */
  sprintf (outfile, "-o %s t%s", exp_name, exp_name);
  run (as_name, outfile);
  if (dontdeltemps == 0)
    {
      sprintf (outfile, "t%s", exp_name);
      unlink (outfile);
    }
}

static char *
xlate (char *name)
{
  if (add_underscore)
    {
      char *copy = malloc (strlen (name) + 2);
      copy[0] = '_';
      strcpy (copy + 1, name);
      name = copy;
    }

  if (killat)
    {
      char *p;
      p = strchr (name, '@');
      if (p)
	*p = 0;
    }
  return name;
}

/**********************************************************************/

static void dump_iat (f, exp)
FILE *f;
export_type *exp;
{
  if (exp->noname && !show_allnames ) 
    {
      fprintf (f, "\t%s\t0x%08x\n",
	       ASM_LONG,
	       exp->ordinal | 0x80000000); /* hint or orindal ?? */
    }
  else
    {
      fprintf (f, "\t%sID%d%s\n", ASM_RVA_BEFORE,
	       exp->ordinal,
	       ASM_RVA_AFTER);
    }
}
static void
gen_lib_file ()
{
  int i;
  int sol;
  FILE *f;
  export_type *exp;
  char *output_filename;
  char prefix[PATHMAX];

  sprintf (outfile, "%s", imp_name);
  output_filename = strdup (outfile);

  unlink (output_filename);

  strcpy (prefix, "d");
  sprintf (outfile, "%sh.s", prefix);

  f = fopen (outfile, "w");

  fprintf (f, "%s IMAGE_IMPORT_DESCRIPTOR\n", ASM_C);
  fprintf (f, "\t.section	.idata$2\n");

  fprintf (f, "\t%s\t__%s_head\n", ASM_GLOBAL, imp_name_lab);
  fprintf (f, "__%s_head:\n", imp_name_lab);

  fprintf (f, "\t%shname%s\t%sPtr to image import by name list\n",
	   ASM_RVA_BEFORE, ASM_RVA_AFTER, ASM_C);

  fprintf (f, "\t%sthis should be the timestamp, but NT sometimes\n", ASM_C);
  fprintf (f, "\t%sdoesn't load DLLs when this is set.\n", ASM_C);
  fprintf (f, "\t%s\t0\t%s loaded time\n", ASM_LONG, ASM_C);
  fprintf (f, "\t%s\t0\t%s Forwarder chain\n", ASM_LONG, ASM_C);
  fprintf (f, "\t%s__%s_iname%s\t%s imported dll's name\n",
	   ASM_RVA_BEFORE,
	   imp_name_lab,
	   ASM_RVA_AFTER,
	   ASM_C);
  fprintf (f, "\t%sfthunk%s\t%s pointer to firstthunk\n",
	   ASM_RVA_BEFORE,
	   ASM_RVA_AFTER, ASM_C);

  fprintf (f, "%sStuff for compatibility\n", ASM_C);
  fprintf (f, "\t.section\t.idata$5\n");
  fprintf (f, "\t%s\t0\n", ASM_LONG);
  fprintf (f, "fthunk:\n");
  fprintf (f, "\t.section\t.idata$4\n");

  fprintf (f, "\t%s\t0\n", ASM_LONG);
  fprintf (f, "\t.section	.idata$4\n");
  fprintf (f, "hname:\n");

  fclose (f);

  sprintf (outfile, "-o %sh.o %sh.s", prefix, prefix);
  run (as_name, outfile);

  for (i = 0; exp = d_exports_lexically[i]; i++)
    {
      sprintf (outfile, "%ss%d.s", prefix, i);
      f = fopen (outfile, "w");
      fprintf (f, "\t.text\n");
      fprintf (f, "\t%s\t%s%s\n", ASM_GLOBAL, ASM_PREFIX, exp->name);
      fprintf (f, "\t%s\t__imp_%s\n", ASM_GLOBAL, exp->name);
      fprintf (f, "%s%s:\n\t%s\t__imp_%s\n", ASM_PREFIX,
	       exp->name, ASM_JUMP, exp->name);

      fprintf (f, "\t.section\t.idata$7\t%s To force loading of head\n", ASM_C);
      fprintf (f, "\t%s\t__%s_head\n", ASM_LONG, imp_name_lab);


      fprintf (f,"%s Import Address Table\n", ASM_C);

      fprintf (f, "\t.section	.idata$5\n");
      fprintf (f, "__imp_%s:\n", exp->name);

      dump_iat (f, exp);

      fprintf (f, "\n%s Import Lookup Table\n", ASM_C);
      fprintf (f, "\t.section	.idata$4\n");

      dump_iat (f, exp);

      if(!exp->noname || show_allnames) 
	{
	  fprintf (f, "%s Hint/Name table\n", ASM_C);
	  fprintf (f, "\t.section	.idata$6\n");
	  fprintf (f, "ID%d:\t%s\t%d\n", exp->ordinal, ASM_SHORT, exp->hint);      
	  fprintf (f, "\t%s\t\"%s\"\n", ASM_TEXT, xlate (exp->name));
	}

      fclose (f);


      sprintf (outfile, "-o %ss%d.o %ss%d.s", prefix, i, prefix, i);
      run (as_name, outfile);
    }

  sprintf (outfile, "%st.s", prefix);
  f = fopen (outfile, "w");
  fprintf (f, "\t.section	.idata$7\n");
  fprintf (f, "\t%s\t__%s_iname\n", ASM_GLOBAL, imp_name_lab);
  fprintf (f, "__%s_iname:\t%s\t\"%s\"\n",
	   imp_name_lab, ASM_TEXT, dll_name);


  fprintf (f, "\t.section	.idata$4\n");
  fprintf (f, "\t%s\t0\n", ASM_LONG);

  fprintf (f, "\t.section	.idata$5\n");
  fprintf (f, "\t%s\t0\n", ASM_LONG);
  fclose (f);

  sprintf (outfile, "-o %st.o %st.s", prefix, prefix);
  run (as_name, outfile);

  /* Now stick them all into the archive */


  sprintf (outfile, "crs %s %sh.o %st.o", output_filename, prefix, prefix);
  run (ar_name, outfile);

  /* Do the rest in groups of however many fit into a command line */
  sol = 0;
  for (i = 0, exp = d_exports; exp; i++, exp = exp->next)
    {
      if (sol == 0)
	{
	  sprintf (outfile, "crs %s", output_filename);
	  sol = strlen (outfile);
	}

      sprintf (outfile + sol, " %ss%d.o", prefix, i);
      sol = strlen (outfile);

      if (sol > 100)
	{
	  run (ar_name, outfile);
	  sol = 0;
	}

    }
  if (sol)
    run (ar_name, outfile);

  /* Delete all the temp files */

  if (dontdeltemps == 0)
    {
      sprintf (outfile, "%sh.o", prefix);
      unlink (outfile);
      sprintf (outfile, "%sh.s", prefix);
      unlink (outfile);
      sprintf (outfile, "%st.o", prefix);
      unlink (outfile);
      sprintf (outfile, "%st.s", prefix);
      unlink (outfile);
    }

  if (dontdeltemps < 2)
    for (i = 0, exp = d_exports; exp; i++, exp = exp->next)
      {
	sprintf (outfile, "%ss%d.o", prefix, i);
	unlink (outfile);
	sprintf (outfile, "%ss%d.s", prefix, i);
	unlink (outfile);
      }

}
/**********************************************************************/

/* Run through the information gathered from the .o files and the
   .def file and work out the best stuff */
int
pfunc (a, b)
     void *a;
     void *b;
{
  export_type *ap = *(export_type **) a;
  export_type *bp = *(export_type **) b;
  if (ap->ordinal == bp->ordinal)
    return 0;

  /* unset ordinals go to the bottom */
  if (ap->ordinal == -1)
    return 1;
  if (bp->ordinal == -1)
    return -1;
  return (ap->ordinal - bp->ordinal);
}


int
nfunc (a, b)
     void *a;
     void *b;
{
  export_type *ap = *(export_type **) a;
  export_type *bp = *(export_type **) b;

  return (strcmp (ap->name, bp->name));
}

static
void
remove_null_names (ptr)
     export_type **ptr;
{
  int src;
  int dst;
  for (dst = src = 0; src < d_nfuncs; src++)
    {
      if (ptr[src])
	{
	  ptr[dst] = ptr[src];
	  dst++;
	}
    }
  d_nfuncs = dst;
}

static void
dtab (ptr)
     export_type **ptr;
{
#ifdef SACDEBUG
  int i;
  for (i = 0; i < d_nfuncs; i++)
    {
      if (ptr[i])
	{
	  printf ("%d %s @ %d %s%s\n",
		  i, ptr[i]->name, ptr[i]->ordinal,
		  ptr[i]->noname ? "NONAME " : "",
		  ptr[i]->constant ? "CONSTANT" : "");
	}
      else
	printf ("empty\n");
    }
#endif
}

static void
process_duplicates (d_export_vec)
     export_type **d_export_vec;
{
  int more = 1;
  int i;  
  while (more)
    {

      more = 0;
      /* Remove duplicates */
      qsort (d_export_vec, d_nfuncs, sizeof (export_type *), nfunc);

      dtab (d_export_vec);
      for (i = 0; i < d_nfuncs - 1; i++)
	{
	  if (strcmp (d_export_vec[i]->name,
		      d_export_vec[i + 1]->name) == 0)
	    {

	      export_type *a = d_export_vec[i];
	      export_type *b = d_export_vec[i + 1];

	      more = 1;
	      if (verbose)
		fprintf (stderr, "Warning, ignoring duplicate EXPORT %s %d,%d\n",
			 a->name,
			 a->ordinal,
			 b->ordinal);
	      if (a->ordinal != -1
		  && b->ordinal != -1)
		{

		  fprintf (stderr, "Error, duplicate EXPORT with oridinals %s\n",
			   a->name);
		  exit (1);
		}
	      /* Merge attributes */
	      b->ordinal = a->ordinal > 0 ? a->ordinal : b->ordinal;
	      b->constant |= a->constant;
	      b->noname |= a->noname;
	      d_export_vec[i] = 0;
	    }

	  dtab (d_export_vec);
	  remove_null_names (d_export_vec);
	  dtab (d_export_vec);
	}
    }


  /* Count the names */
  for (i = 0; i < d_nfuncs; i++)
    {
      if (!d_export_vec[i]->noname)
	d_named_nfuncs++;
    }
}

static void
fill_ordinals (d_export_vec)
     export_type **d_export_vec;
{
  int lowest = 0;
  int unset = 0;
  int hint = 0;
  int i;
  char *ptr;
  qsort (d_export_vec, d_nfuncs, sizeof (export_type *), pfunc);

  /* fill in the unset ordinals with ones from our range */

  ptr = (char *) malloc (65536);

  memset (ptr, 65536, 0);

  /* Mark in our large vector all the numbers that are taken */
  for (i = 0; i < d_nfuncs; i++)
    {
      if (d_export_vec[i]->ordinal != -1)
	{
	  ptr[d_export_vec[i]->ordinal] = 1;
	  if (lowest == 0)
	    lowest = d_export_vec[i]->ordinal;
	}
    }

  for (i = 0; i < d_nfuncs; i++)
    {
      if (d_export_vec[i]->ordinal == -1)
	{
	  int j;
	  for (j = lowest; j < 65536; j++)
	    if (ptr[j] == 0)
	      {
		ptr[j] = 1;
		d_export_vec[i]->ordinal = j;
		goto done;
	      }

	  for (j = 1; j < lowest; j++)
	    if (ptr[j] == 0)
	      {
		ptr[j] = 1;
		d_export_vec[i]->ordinal = j;
		goto done;
	      }
	done:;

	}
    }

  free (ptr);

  /* And resort */

  qsort (d_export_vec, d_nfuncs, sizeof (export_type *), pfunc);


  /* Work out the lowest ordinal number */
  if (d_export_vec[0])
    d_low_ord = d_export_vec[0]->ordinal;
  if (d_nfuncs) {
  if (d_export_vec[d_nfuncs-1])
    d_high_ord = d_export_vec[d_nfuncs-1]->ordinal;
}
}

int alphafunc(av,bv)
void *av;
void *bv;
{
  export_type **a = av;
  export_type **b = bv;

  return strcmp ((*a)->name, (*b)->name);
}

void
mangle_defs ()
{
  /* First work out the minimum ordinal chosen */

  export_type *exp;
  int lowest = 0;
  int i;
  int hint = 0;
  export_type **d_export_vec
  = (export_type **) xmalloc (sizeof (export_type *) * d_nfuncs);

  for (i = 0, exp = d_exports; exp; i++, exp = exp->next)
    {
      d_export_vec[i] = exp;
    }

  process_duplicates (d_export_vec);
  fill_ordinals (d_export_vec);

  /* Put back the list in the new order */
  d_exports = 0;
  for (i = d_nfuncs - 1; i >= 0; i--)
    {
      d_export_vec[i]->next = d_exports;
      d_exports = d_export_vec[i];
    }

  /* Build list in alpha order */
  d_exports_lexically = (export_type **)xmalloc (sizeof(export_type *)*(d_nfuncs+1));

  for (i = 0, exp = d_exports; exp; i++, exp = exp->next)
    {
      d_exports_lexically[i] = exp;
    }
  d_exports_lexically[i] = 0;

  qsort (d_exports_lexically, i, sizeof (export_type *), alphafunc);

  /* Fill exp entries with their hint values */
  
  for (i = 0; i < d_nfuncs; i++)
    {
      if (!d_exports_lexically[i]->noname || show_allnames)
	d_exports_lexically[i]->hint = hint++;
    }

}



  /* Work out exec prefix from the name of this file */
void
workout_prefix ()
{
  char *ps = 0;
  char *s = 0;
  char *p;
  /* See if we're running in a devo tree */
  for (p = program_name; *p; p++)
    {
      if (*p == '/' || *p == '\\')
	{
	  ps = s;
	  s = p;
	}
    }

  if (ps && strncmp (ps, "/binutils", 9) == 0)
    {
      /* running in the binutils directory, the other
         executables will be surrounding it in the usual places. */
      int len = ps - program_name;
      ar_name = xmalloc (len + strlen ("/binutils/ar") + 1);
      ranlib_name = xmalloc (len + strlen ("/binutils/ranlib") + 1);
      as_name = xmalloc (len + strlen ("/gas/as.new") + 1);

      memcpy (ar_name, program_name, len);
      strcpy (ar_name + len, "/binutils/ar");
      memcpy (ranlib_name, program_name, len);
      strcpy (ranlib_name + len, "/binutils/ranlib");
      memcpy (as_name, program_name, len);
      strcpy (as_name + len, "/gas/as.new");
    }
  else
    {
      /* Otherwise chop off any prefix and use it for the rest of the progs,
         so i386-win32-dll generates i386-win32-ranlib etc etc */

      for (p = program_name; *p; p++)
	{
	  if (strncmp (p, "dlltool", 7) == 0)
	    {
	      int len = p - program_name;
	      ar_name = xmalloc (len + strlen ("ar") + 1);
	      ranlib_name = xmalloc (len + strlen ("ranlib") + 1);
	      as_name = xmalloc (len + strlen ("as") + 1);

	      memcpy (ar_name, program_name, len);
	      strcpy (ar_name + len, "ar");
	      memcpy (ranlib_name, program_name, len);
	      strcpy (ranlib_name + len, "ranlib");
	      memcpy (as_name, program_name, len);
	      strcpy (as_name + len, "as");
	    }
	}
    }
}


/**********************************************************************/

void
usage (file, status)
     FILE *file;
     int status;
{
  fprintf (file, "Usage %s <options> <object-files>\n", program_name);
  fprintf (file, "   --machine <machine>\n");
  fprintf (file, "   --output-exp <outname> Generate export file.\n");
  fprintf (file, "   --output-lib <outname> Generate input library.\n");
  fprintf (file, "   --add-indirect         Add dll indirects to export file.\n");
  fprintf (file, "   --dllname <name>       Name of input dll to put into output lib.\n");
  fprintf (file, "   --def <deffile>        Name input .def file\n");
  fprintf (file, "   --output-def <deffile> Name output .def file\n");
  fprintf (file, "   --base-file <basefile> Read linker generated base file\n");
  fprintf (file, "   -v                     Verbose\n");
  fprintf (file, "   -U                     Add underscores to .lib\n");
  fprintf (file, "   -k                     Kill @<n> from exported names\n");
  fprintf (file, "   --nodelete             Keep temp files.\n");
  exit (status);
}

static struct option long_options[] =
{
  {"nodelete", no_argument, NULL, 'n'},
  {"dllname", required_argument, NULL, 'D'},
  {"output-exp", required_argument, NULL, 'e'},
  {"output-def", required_argument, NULL, 'z'},
  {"output-lib", required_argument, NULL, 'l'},
  {"def", required_argument, NULL, 'd'},
  {"add-underscore", no_argument, NULL, 'U'},
  {"killat", no_argument, NULL, 'k'},
  {"help", no_argument, NULL, 'h'},
  {"machine", required_argument, NULL, 'm'},
  {"add-indirect", no_argument, NULL, 'a'},
  {"base-file", required_argument, NULL, 'b'},
  0
};



int
main (ac, av)
     int ac;
     char **av;
{
  int c;
  int i;
  char *firstarg = 0;
  program_name = av[0];
  oav = av;

  while ((c = getopt_long (ac, av, "uaD:l:e:nkvbUh?m:yd:", long_options, 0)) != EOF)
    {
      switch (c)
	{
	  /* ignored for compatibility */
	case 'u':
	  break;
	case 'a':
	  add_indirect = 1;
	  break;
	case 'z':
	  output_def = fopen (optarg, "w");
	  break;
	case 'D':
	  dll_name = optarg;
	  break;
	case 'l':
	  imp_name = optarg;
	  break;
	case 'e':
	  exp_name = optarg;
	  break;
	case 'h':
	case '?':
	  usage (stderr, 0);
	  break;
	case 'm':
	  mname = optarg;
	  break;
	case 'v':
	  verbose = 1;
	  break;
	case 'y':
	  yydebug = 1;
	  break;
	case 'U':
	  add_underscore = 1;
	  break;
	case 'k':
	  killat = 1;
	  break;
	case 'd':
	  def_file = optarg;
	  break;
	case 'n':
	  dontdeltemps++;
	  break;
	case 'b':
	  base_file = fopen (optarg, "r");
	  if (!base_file)
	    {
	      fprintf (stderr, "%s: Unable to open base-file %s\n",
		       av[0],
		       optarg);
	      exit (1);
	    }
	  break;
	default:
	  usage (stderr, 1);
	}
    }


  for (i = 0; mtable[i].type; i++)
    {
      if (strcmp (mtable[i].type, mname) == 0)
	break;
    }

  if (!mtable[i].type)
    {
      fprintf (stderr, "Machine not supported\n");
      exit (1);
    }
  machine = i;


  if (!dll_name && exp_name)
    {
      char len = strlen (exp_name) + 5;
      dll_name = xmalloc (len);
      strcpy (dll_name, exp_name);
      strcat (dll_name, ".dll");
    }
  workout_prefix ();


  if (def_file)
    {
      process_def_file (def_file);
    }
  while (optind < ac)
    {
      if (!firstarg)
	firstarg = av[optind];
      scan_obj_file (av[optind]);
      optind++;
    }


  mangle_defs ();

  if (exp_name)
    gen_exp_file ();
  if (imp_name)
    {
      /* Make imp_name safe for use as a label. */
      char *p;
      imp_name_lab = strdup (imp_name);
      for (p = imp_name_lab; *p; *p++)
	{
	  if (!isalpha (*p) && !isdigit (*p))
	    *p = '_';
	}
      gen_lib_file ();
    }
  if (output_def)
    gen_def_file ();

  return 0;
}
