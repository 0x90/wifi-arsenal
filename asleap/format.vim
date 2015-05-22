"A SCRIPT TO JUSTIFY PLAIN TEXT TO CURRENT TEXT WIDTH
"GOES TO TOP OF CURRENT PARA, CLEANS UP TRAILING AND EXTRA SPACES.
"USES VIMS : gqap TO FORMAT CURRENT PARA
"JUSTIFIES TEXT BY ALTERNATELY INSERTING SPACES FROM START AND END IF REQUIRED

"FOLKS I AM NEW TO VIM... ANY FEEDBACK WOULD BE MOST WELCOME AT
"	kartik_murari@yahoo.com

fu! FORMAT()
	exe ':normal {j'                        
	let top=line(".")
	exe ':normal }k'
	let bot=line(".")
	let todo=bot-top
	let tw=&tw
	exe ':%s+^ *++ge'
	exe ':%s+ *$++ge'
	exe ':'.top.','.bot.'s+ \{2,}+ +ge'
	exe ';normal gqap'
	exe ':'.top
	let curln=strlen(getline("."))
	exe ':normal j'
	let nxtln=strlen(getline("."))
	exe ':normal k'
	while todo
		if curln>0 && nxtln>0
			let xs=tw-curln
			exe ':normal ^'
			while xs
				exe ':normal wi w'
				let xs=xs-1
			endwhile
		endif
		let todo=todo-1
		if todo==0
			break
		endif		
		let curln=nxtln
		exe ':normal jj'
		let nxtln=strlen(getline("."))
		exe ':normal k$'
		if curln>0 && nxtln>0
            let xs=tw-curln
            while xs
                exe ':normal bi b'
                let xs=xs-1
            endwhile
        endif
		let curln=nxtln
		exe ':normal jj'
		let nxtln=strlen(getline("."))
		exe ':normal k'
		let todo=todo-1
	endwhile
	exe ':'.top
endf
