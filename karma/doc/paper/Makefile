all: pdf

pdf: aawns.tex aawns.bib
	pdflatex aawns.tex && bibtex aawns && pdflatex aawns.tex && pdflatex aawns.tex

view: pdf
	gv aawns.pdf
