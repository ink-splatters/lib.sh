" Enabling filetype support provides filetype-specific indenting,
" syntax highlighting, omni-completion and other useful settings.
filetype plugin indent on
syntax on


" `matchit.vim` is built-in so let's enable it!
" Hit `%` on `if` to jump to `else`.
runtime macros/matchit.vim

" various settings
set autoindent                 " Minimal automatic indenting for any filetype.
set backspace=indent,eol,start " Intuitive backspace behavior.
set hidden                     " Possibility to have more than one unsaved buffers.
set incsearch                  " Incremental search, hit `<CR>` to stop.
set ruler                      " Shows the current line number at the bottom-right
                               " of the screen.
set wildmenu                   " Great command-line completion, use `<Tab>` to move
                               " around and `<CR>` to validate.

:colorscheme sorbet

set wrap
set linebreak
" note trailing space at end of next line
set showbreak=>\ \ \

set shiftwidth=4 smarttab
set tabstop=8 softtabstop=0

let g:better_whitespace_enabled=1
let g:strip_whitespace_on_save=1

let g:rcsv_delimiters = ["\t", ",", "^", "~#~"]
let g:rcsv_colorpairs = [['red', 'red'], ['blue', 'blue'], ['green', 'green'], ['magenta', 'magenta'], ['NONE', 'NONE'], ['darkred', 'darkred'], ['darkblue', 'darkblue'], ['darkgreen', 'darkgreen'], ['darkmagenta', 'darkmagenta'], ['darkcyan', 'darkcyan']]
