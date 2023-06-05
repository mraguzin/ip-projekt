""" Attempt #1
Jezik za obradu mikoloških uzoraka i njihovu klasifikaciju. Podržava string i number (interno uvijek double tj. Python float) tipove te 
standardne aritmetičke i logičke operatore iz C-a (uključujući i ternarni). Posebni dodaci:
    * tip podataka koji daje indikaciju razine jestivosti ili razine otrovnosti/toksičnosti (postoji samo konačan skup za selekciju ovih vrijednosti);
    * tip podataka koji reprezentira relevantne biomarkere/otiske/DNA (TODO: provjeriti sa stručnjakom što bi točno trebalo biti ovdje tj.
    koje su vrijednosti itd., ja poznam nekog tko zna sve to.)
    * tip podatka koji reprezentira hijerarhiju; ovo služi za formalno smještanje pojedinih gljiva unutar Linneove ili slične (najvjerojatnije složenije)
    taksonomije (varijanta, vrsta, rod, familija,...)
    * operator za dodjelu statusa jestivosti/toksičnosti itd. nekoj gljivi; ona se identificira imenom varijable koje prethodno mora biti
    registrirano kao ime gljive, za što služi. Primjer: ako je varijabla 'fung' gljiva, tada fung <- edible; označava tu gljivu kao jestivu
    * operator deklaracije gljive: na neki način i ovo je
    operator (a la operator new u C++u) koji pripremi sve potrebne info o gljivi: hrvatsko ime, stručno latinsko ime,
    klasifikaciju (hijerarhija), mjesto pronalaska, datum, masa,... TODO: što sve tu treba? 
    * operator deklaracije hijerarhije: ovo služi da proglasi neku varijablu hijerarhijom, kako bi se ona onda mogla koristiti pri deklaraciji pojedine gljive.
    Sa hijerarhijama se *ne može* raditi izvan varijabli, tj. one ne mogu biti literali (unose se peacemeal)!
    * operator dodavanja novog elementa hijerarhije u već postojeću: ako je hijerarhija u varijabli 'hij', onda hij.fam = 'famxyz';
    mijenja (ili dodaje, ako familija nije prethodno bila dodijeljena) 'famxyz' kao novu familiju hijerarhije 'hij'.
    * gljive kao objekti su imutabilni
    
    
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
    EQ, LT, GT, PLUS, MINUS, PUTA, DIV, OTV, ZATV, LVIT, DVIT, LUGL, DUGL, SEMI, COLON, UPIT, COMMA = '=<>+-*/(){}[];:?,'
    ASGN, NEQ, LE, GE = ':=', '!=', '<=', '>='
    AND, OR, NOT = 'and', 'or', 'not'
    LET, STRING, NUMBER, BOOL, FUNGUS, TREE, EDIBILITY, DNA, DATETIME = 'let', 'string', 'number', 'bool', 'fungus', 'tree', 'edibility',
    'dna', 'datetime' # ključne riječi
    DEADLY, TOXIC1, TOXIC2, EDIBLE = 'deadly', 'toxic1', 'toxic2', 'edible' #TODO
    SPECIES, GENUS, FAMILY, ORDER, CLASS, PHYLUM, KINGDOM = 'spec', 'gen', 'fam', 'ord', 'class', 'phyl', 'king' #TODO: jel ovo ok?
    #https://en.wikipedia.org/wiki/Taxonomy_mnemonic   
    MILIGRAM, GRAM, KILOGRAM = 'mg', 'g', 'kg'
    FUNCTION, RETURN = 'function', 'return'
    CONTINUE, BREAK = 'continue', 'break'
    FOR, IF = 'for', 'if'
    TRUE, FALSE = 'true', 'false'

    class DOT(Token): pass
    class ARROW(Token): pass
    class DNASTART(Token): pass
    class DNAEND(Token): pass
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
                    elif idući == '\n': # ovo je za prijelaz u novi red kad se stavi \ na samom kraju linije, što *ne smije* rezultirati u \n u samom stringu!
                        pass
                    else:
                        ret += idući
                    i += 2
                else:
                    ret += znak
                    i += 1
            return ret
    class DATUM(Token):
        def vrijednost(self):
            try:
                return [int(dio) for dio in self.sadržaj.split('.')]
            except ValueError:
                raise SemantičkaGreška('Krivi format datuma')
        
        def validiraj(self):
            dijelovi = self.vrijednost()
            if dijelovi[0] < 0 or dijelovi[0] > 31 or dijelovi[1] > 12 or dijelovi[1] < 1 or dijelovi[2] < 1000 or dijelovi[2] > 9999:
                raise SemantičkaGreška('Nemoguć datum')
            
            return True
            
    class READ(Token):
        literal = 'read'
    class WRITE(Token):
        literal = 'write'

alias = {'<-': T.ARROW, 'is': T.ARROW, '.': T.DOT, 'part': T.DOT, '[': T.DNASTART, 'DNAstart': T.DNASTART, ']': T.DNAEND, 'DNAend': T.DNAEND}

@lexer
def miko(lex):
    for znak in lex:
        if znak == '#':
            lex * {lambda x: x != '\n'} # moramo ovako jer želimo da bude legalno ostaviti  #    do samog kraja datoteke (tj. datoteka završi u komentaru)
            lex.zanemari()
        elif znak.isdigit():
            lex * {str.isdigit, '.'}
            if lex.sadržaj.count('.') == 3: # poseban slučaj za datume, oni se mogu odmah lexati kao takvi: 26.3.2023. Ali jasno treba dodatan check u parseru...
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
            if lex.sadržaj in alias:
                yield lex.token(alias[lex.sadržaj])
            else:
                yield lex.literal_ili(T.IME)
        elif znak == ':':
            lex >= '='
            yield lex.literal(T)
        elif znak == '<':
            lex >= '='
            lex >= '-'
            yield lex.literal_ili(alias[lex.sadržaj])
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
            yield lex.literal_ili(alias[lex.sadržaj])

#imamo tipove: string, number, bool, fungus, tree, edibility, dna, datetime
#AUTO, STRING, NUMBER, BOOL, FUNGUS, TREE, EDIBILITY, DNA, DATETIME
    #DEADLY, TOXIC1, TOXIC2, EDIBLE = 'deadly', 'toxic1', 'toxic2', 'edible'

## BKG:
# start -> (stmt | fun)+
# type -> (STRING | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DNA | DATETIME)
# decl -> LET IME | LET asgn
# asgn -> IME ASGN expr | IME ARROW expr
# expr -> expr2 UPIT expr COLON expr | expr2
# expr2 -> expr2 OR expr3 | expr3
# expr3 -> expr3 AND expr4 | expr4
# expr4 -> (term PLUS)+ term | (term MINUS)+ term | term
# term -> (fact PUTA)+ fact | (fact DIV)+ fact | fact     #TODO: implicitno množenje
# fact -> fact DOT bot | bot
# bot -> IME | BROJ unit? | STRING | TRUE | FALSE | MINUS bot | NOT bot | OTV expr ZATV | cons | edb | dnaspec | datespec
# unit -> MILIGRAM | GRAM | KILOGRAM
# cons -> type OTV args? ZATV   # konstruktori za builtin tipove
# fun -> FUNCTION OTV params? ZATV LVIT (stmt | RETURN expr SEMI)* DVIT
# params -> IME COMMA params | IME
# stmt -> forloop | branch | call SEMI | expr SEMI | decl SEMI | asgn SEMI
# stmt2 -> CONTINUE SEMI | BREAK SEMI | stmt
# forloop -> FOR IME LVIT stmt2* DVIT | FOR IME stmt2
# branch -> IF OTV expr ZATV stmt | IF OTV expr ZATV LVIT stmt* DVIT
# call -> (IME|READ|WRITE) OTV args? ZATV
# args -> expr COMMA args | expr
# dnaspec -> DNASTART params+ DNAEND  #ovdje pojedina imena moraju biti iz {A,T,C,G}; to se provjerava tijekom parsiranja
## datespec -> DATUM timespec? | BROJ DOT BROJ DOT BROJ DOT timespec? #ovo bi bilo fleksibilnije pravilo s korisničke strane, ali opet izlazi van LL(1) okvira...
# datespec -> DATUM timespec?
# timespec -> BROJ COLON BROJ (COLON BROJ)? 
# edb -> DEADLY | TOXIC1 | TOXIC2 | EDIBLE

#Parser bi trebao biti dvoprolazni radi lakšeg rada s pozivima funkcija za korisnike: program se izvodi kao Python skripta, dakle  kod može biti u globalnom
#scopeu i otamo pozivati štogod je definirano bilo gdje drugdje (uključujući i interne funkcije tj. konstrukture tipova i read+write). Ali vepar nam baš
#ne olakšava takav dizajn, pa je za sada ovo klasični jednoprolazni parser i stoga sve na što se referiramo mora biti već viđeno
class P(Parser):
    def start(p):
        elements = []
        el = p.vidi()
        if el ^ T.FOR:
            elements.append(p.forloop())
        elif el ^ T.IF:
            elements.append(p.branch())
        elif el ^ T.READ or el ^ T.WRITE:
            elements.append(p.call())
        elif el ^ T.IME or el ^ T.BROJ or el ^ T.STRING or el ^ T.MINUS or el ^ T.NOT or el ^ T.OTV or el ^ T.FUNGUS or el ^ T.TREE or el ^ T.DEADLY or el ^ T.TOXIC1 or el ^ T.TOXIC2 or el ^ T.EDIBLE or el ^ T.DATUM:
            elements.append(p.expr()) #tu su ubačeni i call za user-fun i naredbe pridruživanja; disambiguacija se događa tek u expr() (ne može prije jer LL(1))
        elif el ^ T.LET:
            elements.append(p.decl())
        elif el ^ 
