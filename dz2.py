""" Attempt #1
Jezik za obradu mikoloških uzoraka i njihovu klasifikaciju. Podržava string i number (interno uvijek double tj. Python float) tipove te 
standardne aritmetičke i logičke operatore iz C-a (uključujući i ternarni). Posebni dodaci:
    * tip podataka koji daje indikaciju razine jestivosti ili razine otrovnosti/toksičnosti (postoji samo konačan skup za selekciju ovih vrijednosti);
    * tip podataka koji reprezentira relevantne biomarkere/otiske/DNA (TODO: provjeriti sa stručnjakom što bi točno trebalo biti ovdje tj.
    koje su vrijednosti itd., ja poznam nekog tko zna sve to.)
    * tip podatka koji reprezentira hijerarhiju; ovo služi za formalno smještanje pojedinih gljiva unutar Linneove ili slične (najvjerojatnije složenije)
    hijerarhije (varijanta, vrsta, rod, familija,...)
    * operator za dodjelu statusa jestivosti/toksičnosti itd. nekoj gljivi; ona se identificira imenom varijable koje prethodno mora biti
    registrirano kao ime gljive, za što služi
    * operator deklaracije gljive: na neki način i ovo je
    operator (a la operator new u C++u) koji pripremi sve potrebne info o gljivi: hrvatsko ime, stručno latinsko ime,
    klasifikaciju (hijerarhija), mjesto pronalaska, datum, masa,... TODO: što sve tu treba? 
    * operator deklaracije hijerarhije: ovo služi da proglasi neku varijablu hijerarhijom, kako bi se ona onda mogla koristiti pri deklaraciji pojedine gljive.
    Sa hijerarhijama se *ne može* raditi izvan varijabli, tj. one ne mogu biti literali (unose se peacemeal)!
    * operator dodavanja novog elementa hijerarhije u već postojeću: ako je hijerarhija u varijabli 'hij', onda hij.fam = 'famxyz';
    mijenja (ili dodaje, ako familija nije prethodno bila dodijeljena) 'famxyz' kao novu familiju hijerarhije 'hij'.
    
    
Aritmetički izrazi ovdje služe kako bi manipulirali onim podacima gljive koji su brojevi i koji onda služe za definiciju pojedine gljive. Dakle, sveukupno
imamo tipove: string, number, bool, fungus, tree, edibility, dna, datetime
* operator= je overloadan na prirodne načine za: string, number, bool, fungus (deep copy?), tree (deep copy), edibility, dna (shallow copy?),
datetime (deep copy)

*ALTERNATIVNI NAČINI PISANJA OPERATORA: mislim da baš i nema smisla da novi operatori imaju neki kratki simbolički zapis, ali možemo napraviti ovako:
"dugi" zapis je npr. newtree, a "kratki" | ili nešto sl. 

*FILE I/O: builtin funkcije read() i write(), praktički kao u Pythonu; read('datoteka') čita sve iz dane tekstualne datoteke i deserijalizira u
naše interne strukture svakog od mogućih tipova. write('datoteka', obj1, obj2,...) serijalizira objekt 'obj' u danu
tekstualnu datoteku (stvara ju, briše ako postoji). Uočiti da je ovo jedina "funkcija" koja prima varijabilni broj argumenata, t.d. je moguće
lako spremiti cijeli niz objekata.

*KOMENTARI: #
"""

from vepar import *

class T(TipoviTokena):
    EQ, LT, GT, PLUS, MINUS, PUTA, DIV, OTV, ZATV, LVIT, DVIT, SEMI, COLON, UPIT, DOT, COMMA = '=<>+-*/(){};:?.,'
    ASGN, NEQ, LE, GE = ':=', '!=', '<=', '>='
    AND, OR, NOT = 'and', 'or', 'not'
    LET, STRING, NUMBER, BOOL, FUNGUS, TREE, EDIBILITY, DNA, DATETIME = 'let', 'string', 'number', 'bool', 'fungus', 'tree', 'edibility',
    'dna', 'datetime' # ključne riječi
    DEADLY, TOXIC1, TOXIC2, EDIBLE = 'deadly', 'toxic1', 'toxic2', 'edible' #TODO
    SPECIES, GENUS, FAMILY, ORDER, CLASS, PHYLUM, KINGDOM = 'spec', 'gen', 'fam', 'ord', 'class', 'phyl', 'king' #TODO: jel ovo ok?
    #https://en.wikipedia.org/wiki/Taxonomy_mnemonic   
    #RETURN = 'return'   # mislim da ovaj jezik ne treba ništa vraćati iz korisničkih funkcija...?
    MILIGRAM, GRAM, KILOGRAM = 'mg', 'g', 'kg'
    FUNCTION = 'function' #ako nećemo povratne vrijednosti, onda moramo ovako
    CONTINUE, BREAK = 'continue', 'break'
    FOR, IF = 'for', 'if'

    class BROJ(Token):
        def vrijednost(self):
            return float(self.sadržaj)
    class IME(Token): pass
    class STRING(Token):
        def vrijednost(self):
            ret = ''
            i = 1
            while i < len(self.sadržaj)-1:
                znak = self.sadržaj[i]
                if znak == '\\':
                    idući = self.sadržaj[i+1]
                    if idući == '\\':
                        ret += '\\'
                    elif idući == 't':
                        ret += '\t'
                    elif idući == '\n':
                        ret += '\n'
                    else:
                        ret += idući
                    i += 2
                else:
                    ret += znak
                    i += 1
            return ret
    class DATUM(Token): pass
    class READ(Token):
        literal = 'read'
    class WRITE(Token):
        literal = 'write'

@lexer
def miko(lex):
    for znak in lex:
        if znak == '#':
            lex * '\n'
            lex.zanemari()
        elif znak.isdigit():
            lex * {str.isdigit, '.'}
            if lex.sadržaj.count('.') == 3: # poseban slučaj za datume, oni se mogu odmah lexati kao datumi: 26.3.2023. Ali jasno treba dodatan check u parseru...
                if len(lex.sadržaj) < 6:
                    lex.greška('Ilegalan format datuma') #TODO: detaljni error reporting za datume u fazi parsiranja
                else:
                    yield lex.token(T.DATUM)
            else:
                try:
                    test = float(lex.sadržaj)
                except ValueError:
                    lex.greška('Ilegalan format broja')
                yield lex.token(T.BROJ)
        elif znak.isalpha():
            lex * {str.isalnum, '_'}
            yield lex.literal_ili(T.IME)
        elif znak == ':':
            lex >= '='
            yield lex.literal(T)
        elif znak == '<':
            lex >= '='
            yield lex.literal(T)
        elif znak == '>':
            lex >= '='
            yield lex.literal(T)
        elif znak == '!':
            lex >> '='
            yield lex.literal(T)
        elif znak == '"': # mislim da za ovakav jezik nema smisla podržavati mnoge escape sekvence, jer ovo nije primarno programski jezik
            while True:
                idući = lex - {'\\', '"'}
                if idući == '\\':
                    if lex >= {'\\', '"'}:
                        pass
                    pass
                elif idući == '"':
                    yield lex.token(T.STRING)
                    break                    
        elif znak.isspace():
            lex.zanemari()
        else:
            yield lex.literal(T)

#imamo tipove: string, number, bool, fungus, tree, edibility, dna, datetime
#AUTO, STRING, NUMBER, BOOL, FUNGUS, TREE, EDIBILITY, DNA, DATETIME
    #DEADLY, TOXIC1, TOXIC2, EDIBLE = 'deadly', 'toxic1', 'toxic2', 'edible' #TODO

## BKG:
# start -> (stmt | fun)+
# type -> (STRING | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DNA | DATETIME)
# decl -> LET IME | LET asgn
# asgn -> IME ASGN expr
# expr -> expr2 UPIT expr COLON expr | expr2
# expr2 -> expr2 OR expr3 | expr3
# expr3 -> expr3 AND expr4 | expr4
# expr4 -> expr4 PLUS term | expr4 MINUS term | term
# term -> term PUTA fact | term DIV fact | fact
# fact -> IME | BROJ | STRING | MINUS fact | NOT fact | OTV expr ZATV | FUNGUS | TREE | edb | dnaspec | datespec
# fun -> FUNCTION OTV params? ZATV LUGL stmt* DUGL
# params -> IME COMMA params | IME
# stmt2 -> CONTINUE SEMI | BREAK SEMI | forloop | branch | call SEMI | expr SEMI | decl SEMI | asgn SEMI
# stmt -> forloop | branch | call SEMI | expr SEMI | decl SEMI | asgn SEMI
# forloop -> FOR IME LUGL stmt2* DUGL | FOR IME stmt2
# branch -> IF OTV expr ZATV stmt | IF OTV expr ZATV LUGL stmt* DUGL
# call -> (IME|READ|WRITE) OTV args? ZATV
# args -> expr COMMA args | expr
# dnaspec -> TODO
# datespec -> DATUM timespec?
# timespec -> BROJ COLON BROJ (COLON BROJ)?  #moguće je da postoji višeznačnost zbog : u ternarnom operatoru, ali nama dodjela (:=) nije izraz pa je ipak ok
# edb -> DEADLY | TOXIC1 | TOXIC2 | EDIBLE

#Parser bi trebao biti dvoprolazni radi lakšeg rada s pozivima funkcija za korisnike: program se izvodi kao Python skripta, dakle  kod može biti u globalnom
#scopeu i otamo pozivati štogod je definirano bilo gdje drugdje (uključujući i interne funkcije tj. konstrukture tipova i read+write). Ali vepar nam baš
#ne olakšava takav dizajn, pa je za sada ovo klasični jednoprolazni parser i stoga sve na što se referiramo mora biti već viđeno
class P(Parser):
    def start(p):
        elements = []
        el = p.čitaj()
        if el ^ T.FOR:
            elements.append(p.forloop())
        elif el ^ T.IF:
            elements.append(p.branch())
        elif el ^ T.READ or el ^ T.WRITE:
            elements.append(p.call())
        elif el ^ T.IME or el ^ T.BROJ or el ^ T.STRING or el ^ T.MINUS or el ^ T.NOT or el ^ T.OTV or el ^ T.FUNGUS or el ^ T.TREE or el ^ T.DEADLY or el ^ T.TOXIC1 or el ^ T.TOXIC2 or el ^ T.EDIBLE or el ^ el ^ T.DATUM:
            elements.append(p.expr()) #tu su ubačeni i call za user-fun i naredbe pridruživanja; disambiguacija se događa tek u expr() (ne može prije jer LL(1))
        elif el ^ T.LET:
            elements.append(p.decl())
        #elif el ^ 
