"""
Jezik za obradu mikoloških uzoraka i njihovu klasifikaciju. Podržava string i number (interno uvijek double tj. Python float) tipove te 
standardne aritmetičke i logičke operatore iz C-a (uključujući i ternarni). Posebni dodaci:
    * tip podataka koji daje indikaciju razine jestivosti ili razine otrovnosti/toksičnosti (postoji samo konačan skup za selekciju ovih vrijednosti);
    * tip podataka koji reprezentira relevantne biomarkere/otiske/DNA
    * tip podatka koji reprezentira hijerarhiju; ovo služi za formalno smještanje pojedinih gljiva unutar Linneove ili slične (najvjerojatnije složenije)
    taksonomije (varijanta, vrsta, rod, familija,...)
    ==TRI GLAVNA NOVA OPERATORA==
    * operator mutacije dodjeljenog DNA. Npr. ⥼fungus; specificira da se gljiva 'fungus' mutira po konfiguriranoj distribuciji (pri njenoj konstrukciji)
    (https://en.wikipedia.org/wiki/Genetic_operator)
    (https://archive.org/details/geneticprogrammi0000koza/page/n13/mode/2up)
    * operator križanja. Npr. fungus1 ⊗ fungus2; obavlja križanje dvije gljive i vraća njihovo "dijete"
    * operator selekcije. Npr. [fungus1,fungus2,fungus3]⊙; odabire gljivu iz liste po određenom (interno parametrizabilnom) kriteriju. Ovaj operator
    radi samo nad *listama* jedinki! Općenito želimo da sva tri također rade nad listama radi potpunosti.
    * deklaracija gljive: na neki način i ovo je
    operator (a la operator new u C++u) koji pripremi sve potrebne info o gljivi: hrvatsko ime, stručno latinsko ime,
    klasifikaciju (hijerarhija), mjesto pronalaska, datum, masa,...
    * operator deklaracije hijerarhije: ovo služi da proglasi neku varijablu hijerarhijom, kako bi se ona onda mogla koristiti pri deklaraciji pojedine gljive.
    Sa hijerarhijama se *ne može* raditi izvan varijabli, tj. one ne mogu biti literali (unose se peacemeal)!
    * operator dodavanja novog elementa hijerarhije u već postojeću: ako je hijerarhija u varijabli 'hij', onda hij.fam = 'famxyz';
    mijenja (ili dodaje, ako familija nije prethodno bila dodijeljena) 'famxyz' kao novu familiju hijerarhije 'hij'.
    * _svi_ objekti (osim taksonomija, koje se jedino i mogu kompletno izgraditi preko . operatora)
      su imutabilni na razini jezika, ali kompletno mutabilni u smislu genetskih operatora koji se nad njima mogu izvoditi
    
    
Aritmetički izrazi ovdje služe kako bi manipulirali onim podacima gljive koji su brojevi i koji onda služe za definiciju pojedine gljive. Dakle, sveukupno
imamo tipove: string, number, bool, fungus, tree, edibility, dna, datetime
* operator= je overloadan na prirodne načine za: string, number, bool, fungus (shallow), tree (deep copy), edibility, dna (shallow),
datetime (deep copy)

*FILE I/O: builtin funkcije read() i write(), praktički kao u Pythonu; read('datoteka') čita sve iz dane tekstualne datoteke i deserijalizira u
naše interne strukture svakog od mogućih tipova. write('datoteka', obj1, obj2,...) serijalizira objekt 'obj' u danu
tekstualnu datoteku (stvara ju, briše ako postoji). Uočiti da je ovo jedina "funkcija" koja prima varijabilni broj argumenata, t.d. je moguće
lako spremiti cijeli niz objekata.

*KOMENTARI: #
"""

from vepar import *
import copy
import datetime
import jsonpickle

class T(TipoviTokena):
    EQ, LT, GT, PLUS, MINUS, PUTA, DIV, OTV, ZATV, LVIT, DVIT, LUGL, DUGL, SEMI, COLON, UPIT, COMMA, DOT = '=<>+-*/(){}[];:?,.'
    ASGN, NEQ, LE, GE = ':=', '!=', '<=', '>='
    AND, OR, NOT = 'and', 'or', 'not'
    LET = 'let'
    RETURN = 'return'
    # način za eksplicitno deklarirati varijablu nekog builtin tipa npr. number(12) je ekviv. 12. Zagrade su obvezne pri konstrukciji!
    DEADLY, TOXIC1, TOXIC2, EDIBLE = 'deadly', 'toxic1', 'toxic2', 'edible'
    #SPECIES, GENUS, FAMILY, ORDER, CLASS, PHYLUM, KINGDOM = 'spec', 'gen', 'fam', 'ord', 'class', 'phyl', 'king' #
    #^^ovo ne mogu biti zasebni tokeni jer mi statički ne možemo odrediti tip varijable pa da možemo pri parsiranju validirati je li ok pristupanje članovima
    #taksonomijskih objekata (ovo je "dynamically typed language"); koristit ćemo ova posebna *imena* pri izvršavanju, kada znamo da je element
    #kojem se pristupa točka-izrazom upravo tog tipa
    #https://en.wikipedia.org/wiki/Taxonomy_mnemonic   
    MILIGRAM, GRAM, KILOGRAM = 'mg', 'g', 'kg' # jedinice, mogu se koristiti nakon brojeva; jezik podržava pravilno računanje i javlja grešku
    # pri izvođenju ako je u računu s dimenzijama neki element bez eksplicitno navedene jedinice
    FUNCTION = 'function'
    FOR, IF, ELSE = 'for', 'if', 'else'
    TRUE, FALSE = 'true', 'false'


    #class DOT(Token): pass
    class MUTATION(Token): pass
    class CROSSING(Token): pass
    class SELECTION(Token): pass
    class STRINGTYPE(Token): # ovo stavljamo ovdje radi mogućnosti provjera konstruktorskih argumenata
        literal = 'String'
        def validate_call(self, *args):
            if len(args) != 1 or not is_stringetic(args[0]) or is_list(args[0]):
                raise SemantičkaGreška('Konstruktor String-a traži string izraz')
            return True
    class NUMBER(Token):
        literal = 'Number'
        def validate_call(self, *args):
            if len(args) != 1 or not is_arithmetic(args[0]) or is_list(args[0]):
                raise SemantičkaGreška('Konstruktor Number-a traži brojevni izraz')
            return True
    class BOOL(Token):
        literal = 'Bool'
        def validate_call(self, *args):
            if len(args) != 1 or not is_boolean(args[0]) or is_list(args[0]):
                raise SemantičkaGreška('Konstruktor Bool-a traži bool izraz')
            return True
    class FUNGUS(Token):
        literal = 'Fungus'
        def validate_call(self, *args):
            if len(args) != 4 or len(args) != 5: # mora se navesti ime,latinsko ime,dna,taksonomija; opcionalno je još i Datetime pronalaska/unosa uzorka
                raise SemantičkaGreška('Konstruktor Fungus-a traži ime,latinsko ime,DNA,taksonomiju i opcionalno još vrijeme pronalaska')
            if not is_stringetic(args[0]) or is_list(args[0]) or not is_stringetic(args[1]) or is_list(args[1]) or not (args[2] ^ T.IME or args[2] ^ DNA) or not(args[3] ^ T.IME or args[3] ^ ConstructorCall and not args[3].type ^ T.TREE):
                raise SemantičkaGreška('Konstruktor Fungus-a traži ime,latinsko ime,DNA,taksonomiju i opcionalno još vrijeme pronalaska')
            if len(args) == 5 and (not is_datetime(args[4]) or is_list(args[4])):
                raise SemantičkaGreška('Opcionalni argument Fungus konstruktora je datum/vrijeme')
            return True
    class TREE(Token):
        literal = 'Tree'
        def validate_call(self, *args):
            if len(args) > 1:
                raise SemantičkaGreška('Konstruktor Tree-a je bez parametara')
            return True
    class EDIBILITY(Token):
        literal = 'Edibility'
        def validate_call(self, *args):
            if len(args) != 1:
                raise SemantičkaGreška('Konstruktor Edibility-ja traži jednu od kontekstualnih ključnih riječi za jestivost/toksičnost')
            kind = args[0]
            if not (kind ^ T.DEADLY or kind ^ T.TOXIC1 or kind ^ T.TOXIC2 or kind ^ T.EDIBLE):
                raise SemantičkaGreška('Edibility specifikacija mora biti jedna od predefiniranih...')
            return True
    class DNA(Token):
        literal = 'DNA'
        def validate_call(self, *args):
            if len(args) != 1:
                raise SemantičkaGreška("Can't get here")
            return True
    class DATETIME(Token):
        literal = 'Datetime'
        def validate_call(self, *args):
            if len(args) >= 3: # želimo dopustiti da se datum konstruira iz komponenti, koje radi udobnosti mogu biti što god se može interpretirati kao broj
                if not is_arithmetic(args[0]) or not is_arithmetic(args[1]) or not is_arithmetic(args[2]):
                    raise SemantičkaGreška('Datum se konstruira od bar 3 komponente')
                if len(args) >= 5:
                    if not is_arithmetic(args[3]) or not is_arithmetic(args[4]):
                        raise SemantičkaGreška('Vrijeme zahtijeva dva broja')
                return True
            
            if len(args) != 1 or not is_datetime(args[0]) or is_list(args[0]):
                raise SemantičkaGreška('Konstruktor Datetime-a zahtijeva literal datuma ili datuma+vremena')
            return True
    class CONTINUE(Token):
        literal = 'continue'
        def izvrši(self):
            raise Nastavak()
    class BREAK(Token):
        literal = 'break'
        def izvrši(self):
            raise Prekid()
    class BROJ(Token):
        def vrijednost(self):
            return float(self.sadržaj)
        def get_list_length(self):
            return None
    class IME(Token):
        def vrijednost(self):
            symtab = get_symtab(self)
            return symtab[self]
        def get_list_length(self):
            return None
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
                    elif idući == 'n':
                        ret += '\n'
                    elif idući == '\n': # ovo je za prijelaz u novi red kad se stavi \ na samom kraju linije, što *ne smije* rezultirati u \n u samom stringu!
                        pass
                    else:
                        ret += idući
                    i += 2
                else:
                    ret += znak
                    i += 1
            return ret
        def get_list_length(self):
            return None
    class DATUM(Token):
        def vrijednost(self):
            try:
                return [int(dio) for dio in self.sadržaj.split('.')]
            except ValueError:
                raise SemantičkaGreška('Krivi format datuma')
            
        def get_list_length(self):
            return None
        
    class SETPARAM(Token):  #ovo je builtin funkcija koja služi interaktivnoj izmjeni/prilagodbi globalnih parametara evolucijskih operatora
    # kako bi se dobili željeni populacijski rezultati kroz simulirane generacije gljiva.
    # Sami parametri nisu hardkodirani u jeziku ali neki se očekuju pri izvršavanju genetskih operacija. Parametri se predaju kao param:val parovi
    #  i interpreter je dužan nositi se s njima kako spada. Npr. setParam("param1:")
        literal = 'setParam'
        def izvrši(self, *args):
            for key,val in args.items():
                rt.params[key] = val
            return None
            
    class READ(Token):
        literal = 'read'
        def izvrši(self, *args):
            arg = args[0].vrijednost()
            if type(arg) != str:
                raise SemantičkaGreška('Očekivan filename string')
            file = open(arg, 'r')
            lines = ''
            try:
                lines = file.readlines()
            except: raise SemantičkaGreška('Nije uspjelo otvaranje ' + arg)
            try:
                return jsonpickle.decode(lines)
            except: raise SemantičkaGreška('Parsiranje JSON-a nije uspjelo')
        def validate_call(self, *args):
            if len(args) != 1:
                raise SintaksnaGreška('read funkcija očekuje jedan argument: ime JSON datoteke za pročitati')
        def get_list_length(self):
            return None
    class WRITE(Token):
        literal = 'write'
        def izvrši(self, *args):
            fname = args[0].vrijednost()
            if type(fname) != str:
                raise SemantičkaGreška('Prvi argument od write() treba biti filename string')
            file = open(fname, 'w')
            things = []
            for arg in args[1:]:
                things.append(arg)
            if len(things) == 1:
                file.write(jsonpickle.encode(things[0]))
            else:
                file.write(jsonpickle.encode(things)) # strpat ćemo sve u listu ako korisnik šalje više objekata iz programa za zapis; oni će mu se onda
                # pri učitavanju vratiti kao lista
            return None
        def validate_call(self, *args):
            if len(args) < 2:
                raise SemantičkaGreška('write funkcija očekuje bar dva argumenta: 1:datoteku, 2: objekt, više objekata ili listu objekata za zapisati')
        def get_list_length(self):
            return None

alias = {'⥼': T.MUTATION, 'mutate': T.MUTATION, '⊗': T.CROSSING, '⊙': T.SELECTION, 'cross': T.CROSSING, 'select': T.SELECTION}

@lexer
def miko(lex):
    for znak in lex:
        if znak == '#':
            lex * {lambda x: x != '\n'} # moramo ovako jer želimo da bude legalno ostaviti  #    do samog kraja datoteke (tj. datoteka završi u komentaru)
            lex.zanemari()
            continue
        elif znak == '-':
            if znak := lex >= str.isdigit:
                 znak = '1' # nebitno
            else:
                 yield lex.literal(T)
                 continue
        if znak.isdigit():
            lex * {str.isdigit, '.'}
            if lex.sadržaj.count('.') == 3: # poseban slučaj za datume, oni se mogu odmah lexati kao takvi: 26.3.2023. Ali jasno treba dodatan check u parseru...
                if len(lex.sadržaj) < 6:
                    raise lex.greška('Ilegalan format datuma')
                else:
                    yield lex.token(T.DATUM)
            else:
                try:
                    test = float(lex.sadržaj)
                except ValueError:
                    raise lex.greška('Ilegalan format broja')
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
            yield lex.literal(T)
        elif znak == '>':
            lex >= '='
            yield lex.literal(T)
        elif znak == '!':
            lex >> '='
            yield lex.literal(T)
        elif znak == '"': # mislim da za ovakav jezik nema smisla podržavati mnoge escape sekvence, jer ovo nije primarno programski jezik
            while True:
                lex < {'\\', '"'}
                idući = lex.čitaj()
                if idući == '\\':
                    lex.čitaj()
                elif idući == '"':
                    yield lex.token(T.STRING)
                    break                    
        elif znak.isspace():
            lex.zanemari()
        else:
            try:
                if lex.sadržaj in alias:
                    yield lex.token(alias[lex.sadržaj])
                else:
                    yield lex.literal(T)
            except KeyError:
                raise lex.greška()

class GreškaPridruživanja(SintaksnaGreška): """ Zanemariti ovo; gramatika se promijenila i ovo više nema nikakvog značenja! """

#imamo tipove: string, number, bool, fungus, tree, edibility, dna, datetime
#AUTO, STRING, NUMBER, BOOL, FUNGUS, TREE, EDIBILITY, DNA, DATETIME
    #DEADLY, TOXIC1, TOXIC2, EDIBLE = 'deadly', 'toxic1', 'toxic2', 'edible'

## BKG:
# start -> (stmt | fun)+
# type -> STRINGTYPE | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DNA | DATETIME
# nodna -> STRINGTYPE | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DATETIME
# decl -> LET IME | LET asgn
# asgn -> IME ASGN expr
# expr -> expr0 ASGN expr | expr0
# expr0 -> cross UPIT expr0 COLON expr | cross
# cross -> cross CROSSING sel | sel
# sel -> sel SELECTION | mut
# mut -> MUTATION mut | expr2
# expr2 -> expr2 OR expr3 | expr3
# expr3 -> expr3 AND expr5 | expr5
# expr5 -> expr5 EQ expr6 | expr5 NEQ expr6 | expr6
# expr6 -> expr6 LT expr4 | expr6 LE expr4 | expr6 GT expr4 | expr6 GE expr4 | expr4
# expr4 -> (term PLUS)+ term | (term MINUS)+ term | term
# term -> (fact PUTA)+ fact | (fact DIV)+ fact | fact     #TODO: implicitno množenje
# fact -> (bot DOT)+ bot | bot
# bot -> IME | BROJ unit? | STRING | TRUE | FALSE | MINUS bot | NOT bot | OTV expr ZATV | call | cons | edb |
# | datespec | list
# list -> LUGL args? DUGL
# unit -> MILIGRAM | GRAM | KILOGRAM
# cons -> type OTV args? ZATV | DNA LUGL params DUGL | DNA OTV IME ZATV  # konstruktori za builtin tipove
# fun -> FUNCTION IME OTV params? ZATV LVIT (stmt | RETURN expr SEMI)* DVIT
# params -> (IME COMMA)+ IME | IME
# stmt -> forloop | branch | call SEMI | expr SEMI | decl SEMI
# stmt2 -> CONTINUE SEMI | BREAK SEMI | stmt
# forloop -> FOR IME LVIT stmt2* DVIT | FOR IME stmt2
# branch -> IF OTV expr ZATV LVIT stmt* DVIT | IF OTV expr ZATV LVIT stmt* DVIT ELSE LVIT stmt* DVIT  #izbjegavamo dangling else problem s obveznim {}
# call -> (IME|READ|WRITE) OTV args? ZATV
# setparam_call -> SETPARAM OTV setargs ZATV  #poseban slučaj samo za poziv setParam builtin funkcija koja prima isključivo "keyword" argumente
#(druge funkcije to ne mogu; svi argumenti su pozicijski)
# setargs -> (IME COLON expr COMMA)+ IME COLON expr | IME COLON expr
# args -> (expr COMMA)+ expr | expr
## datespec -> DATUM timespec? | BROJ DOT BROJ DOT BROJ DOT timespec? #ovo bi bilo fleksibilnije pravilo s korisničke strane, ali opet izlazi van LL(1) okvira...
# datespec -> DATUM timespec?
# timespec -> BROJ COLON BROJ (COLON BROJ)? 
# edb -> DEADLY | TOXIC1 | TOXIC2 | EDIBLE

#Parser bi trebao biti dvoprolazni radi lakšeg rada s pozivima funkcija za korisnike: program se izvodi kao Python skripta, dakle  kod može biti u globalnom
#scopeu i otamo pozivati štogod je definirano bilo gdje drugdje (uključujući i interne funkcije tj. konstrukture tipova i read+write). Ali vepar nam baš
#ne olakšava takav dizajn, pa je za sada ovo klasični jednoprolazni parser i stoga sve na što se referiramo mora biti već viđeno
# (sigurno ne želimo prototipove)

def is_in_symtable(symbol): # provjerava cijeli stog scopeova za utvrditi je li trenutno deklariran symbol; ne podržavamo ugnježđavanje funkcijskih
    # blokova, pa je max.dubina stoga 2 (globalan i funkcijski scope)
    for i in range(len(rt.symtab)-1, -1, -1):
        if symbol in rt.symtab[i]:
            return True
        
    return False

def is_function_defined(symbol):
    if symbol in rt.funtab:
        return True
    return False

def get_symtab(symbol):
    for i in range(len(rt.symtab)-1, -1, -1):
        if symbol in rt.symtab[i]:
            return i, rt.symtab[i]
        

    # * operator mutacije dodjeljenog DNA. Npr. ⥼fungus; specificira da se gljiva 'fungus' mutira po konfiguriranoj distribuciji (pri njenoj konstrukciji)
    # (https://en.wikipedia.org/wiki/Genetic_operator)
    # (https://archive.org/details/geneticprogrammi0000koza/page/n13/mode/2up)
    # * operator križanja. Npr. fungus1 ⊗ fungus2; obavlja križanje dvije gljive i vraća njihovo "dijete"
    # * operator selekcije. Npr. [fungus1,fungus2,fungus3]⊙; 
def is_fungus(tree):
    if tree ^ Unary and (tree.op ^T.MUTATION or tree.op ^ T.SELECTION):
        return True
    elif tree ^ Binary and tree.op ^ T.CROSSING:
        return True
    elif tree ^ T.IME or tree ^ Call:
        return True
    elif tree ^ ConstructorCall and not tree.type ^ T.FUNGUS:
        return True
    elif tree ^ List:
        for el in tree.elements:
            if not is_fungus(el):
                return False
        return True
    return False
        
def is_arithmetic(tree): # ove stvari su samo za provjeru pri *parsiranju* tj. rade samo na jednoj razini, jer smo pri pozivu u postupku izgradnje izraza
        if tree ^ Unary:
            if tree.op ^ T.MINUS:
                return True
            return False
        elif tree ^ Nary and (tree.pairs[0][0] ^ T.PLUS or tree.pairs[0][0] ^ T.MINUS or tree.pairs[0][0] ^ T.PUTA or tree.pairs[0][0] ^ T.DIV):
            return True
        elif tree ^ Number or tree ^ T.IME or tree ^ Call: # za T.IME mi naravno ne možemo znati pri parsiranju je li to aritmetički ili kakav već tip
            return True
        elif tree ^ ConstructorCall and tree.type ^ T.NUMBER:
            return True
        elif tree ^ List:
            # liste mogu sudjelovati u aritmetičkim operacijama, ali im svi elementi moraju biti imena/brojevi i operacije se rade element-po-element
            for el in tree.elements:
                if not is_arithmetic(el):
                    return False
            return True
        return False

def is_datetime(tree):
        if tree ^ Unary:
            return False
        elif tree ^ Date or tree ^ DateTime or tree ^ T.IME or tree ^ Call:
            return True
        elif tree ^ ConstructorCall and tree.type ^ T.DATETIME:
            return True
        elif tree ^ List:
            for el in tree.elements:
                if not is_datetime(el):
                    return False
            return True
        return False

def is_stringetic(tree):
    if tree ^ Unary:
        return False
    elif tree ^ Nary and tree.pairs[0][0] ^ T.PLUS:
        return True
    elif tree ^ Literal and tree.value ^ T.STRING:
        return True
    elif tree ^ List:
        for el in tree.elements:
            if not is_stringetic(el):
                return False
        return True
    elif tree ^ T.IME or tree ^ Call:
            return True
    elif tree ^ ConstructorCall and tree.type ^ T.STRINGTYPE:
        return True
    return False

def is_boolean(tree):
    if tree ^ Unary:
        if tree.op ^ T.NOT:
            return True
        return False
    elif tree ^ Binary:
        if tree.op ^ T.AND or tree.op ^ T.OR or tree.op ^ T.EQ or tree.op ^ T.NEQ or tree.op ^ T.LE or tree.op ^ T.LT or tree.op ^ T.GE or tree.op ^ T.GT:
            return True
        return False
    elif tree ^ Literal and (tree.value ^ T.TRUE or tree ^ T.FALSE):
        return True
    elif tree ^ List:
        for el in tree.elements:
            if not is_boolean(el):
                return False
        return True
    elif tree ^ T.IME or tree ^ Call:
            return True
    elif tree ^ ConstructorCall and tree.type ^ T.BOOL:
        return True
    return False

def listcheck(checker, *args): # rekurzivna provjera kompatibilnosti listi
        num_lists = 0
        for arg in args:
            if is_list(arg):
                num_lists += 1
        if num_lists > 0 and num_lists < len(args):
            return False
        if num_lists == 0:
            for arg in args:
                if not checker(arg):
                    return False
            return True
        
        # svi su liste
        klen = None
        for alist in args:
            if klen is None:
                if type(alist) == list:
                    klen = len(alist)
                else:
                    klen = alist.get_list_length()
            else:
                if type(alist) == list:
                    if klen != len(alist):
                        return False
                else:
                    if klen != alist.get_list_length():
                        return False
        
        for els in zip(*args):
            if not listcheck(checker, *els):
                return False
        return True

def listcheck_generic(*args):
    return listcheck(lambda x: True, *args)

def listcheck_fungus(*args):
    return listcheck(is_fungus, *args)
    
def listcheck_number(*args): # rekurzivna provjera kompatibilnosti brojevnih listi
    return listcheck(is_arithmetic, *args)

def listcheck_numberunits(*args):
        num_lists = 0
        for arg in args:
            if is_list(arg):
                num_lists += 1
        if num_lists > 0 and num_lists < len(args):
            return False
        if num_lists == 0:
            if not is_arithmetic(args[0]):
                return False
            unit = None
            if args[0] ^ Number and args[0].unit:
                unit = args[0].unit
            for arg in args[1:]:
                if not is_arithmetic(arg):
                    return False
                if not unit:
                    if arg ^ Number and arg.unit:
                        return False
                else:
                    if arg ^ Number and not arg.unit:
                        return False
            return True
        
        # svi su liste
        klen = None
        for alist in args:
            if klen is None:
                if type(alist) == list:
                    klen = len(alist)
                else:
                    klen = alist.get_list_length()
            else:
                if type(alist) == list:
                    if klen != len(alist):
                        return False
                else:
                    if klen != alist.get_list_length():
                        return False
        
        for els in zip(*args):
            if not listcheck_numberunits(*els):
                return False
        return True
    
def listcheck_bool(*args):
    return listcheck(is_boolean, *args)

def units_check(*args):
    num_lists = 0
    for arg in args:
        if is_list(arg):
            num_lists += 1
    if num_lists > 0 and num_lists < len(args):
        return False
    if num_lists == 0:
        if not is_arithmetic(args[0]):
            return False
    unit = None
    for arg in args:
        if unit and is_list(arg):
            return False
        if arg ^ Number and arg.unit:
            if unit:
                return False
            unit = arg.unit
        
        # svi su liste
    klen = None
    for alist in args:
            if klen is None:
                if type(alist) == list:
                    klen = len(alist)
                else:
                    klen = alist.get_list_length()
            else:
                if type(alist) == list:
                    if klen != len(alist):
                        return False
                else:
                    if klen != alist.get_list_length():
                        return False
        
    for els in zip(*args):
        if not units_check(*els):
            return False
    return True


   


    unit = None
    if args[0] ^ Number and args[0].unit:
        unit = args[0].unit
    elif is_list(args[0]):
        return False
    for arg in args[1:]:
        if arg ^ Number and arg.unit:
            if unit:
                return False
            unit = arg.unit
        elif unit:
            if arg ^ Number and arg.unit:
                return False
        if is_list(args[0]):
            return False
            
    return True

def is_list(node): # ovo služi generičkoj provjeri da neki dio AST-a izraza *rezultira* u listi; uočimo da to ne moraju direktno biti liste, već i drugi
    # izrazi za koje statički znamo da daju listu (tj. da im je vrijednost lista). Kada bismo imali neke operatore koji mogu "suziti" rezultat npr. iz
    # liste operanada dati nekakav "skalar" (OTOH operatori usporedbe < i > nad listama brojeva), onda bi ovo bila složenija funkcija.
    if type(node) == list:
        return len(node)
    if node ^ Binary and (node.op ^ T.EQ or node.op ^ T.NEQ): # ipak imamo ovaj važan poseban slučaj
        return False 
    return node.get_list_length() is not None

class P(Parser):
    def start(p):
        rt.symtab = list() # želimo leksički scopeane varijable tj. funkcijski lokalne varijable su vidljive samo unutar funkcije ispod pozicije deklariranja
        # i ne smiju se opetovano deklarirati u istoj funkciji; pri izlasku iz funkcije, parser zaboravlja sve njene lokalne varijable. Zato koristimo stog
        rt.funtab = Memorija() # tu držimo samo (globalne) funkcije
        rt.symtab.append(Memorija()) # globalni scope
        functions = []
        statements = []

        while not p > KRAJ:
            if p > T.FUNCTION:
                functions.append(p.fun())
            else:   
                statements += p.stmts()

        if len(statements) == 0:
            raise p.greška('Program je prazan')
        
        return Program(statements, functions)
    
    # fun -> FUNCTION IME OTV params? ZATV LVIT (stmt | RETURN expr SEMI)* DVIT
    def fun(p):
        p >> T.FUNCTION
        name = p >> T.IME
        #if is_in_symtable(name):
        if name in rt.funtab:
            raise p.greška('Funkcija ' + name.sadržaj + ' je već definirana')
        params = []
        p >> T.OTV
        if not p >= T.ZATV:
            params = p.params()
            p >> T.ZATV
        p >> T.LVIT
        rt.symtab.append(Memorija()) # push
        body = p.body()
        rt.symtab.pop()
        p >> T.DVIT
        rt.funtab[name] = Function(name, params, body)
        return rt.symtab[-1][name]

    def params(p):
        names = [p >> T.IME]
        while p >= T.COMMA: names.append(p >> T.IME)
        return names
    
    def body(p):
        statements = []
        while el := p > {T.MUTATION, T.RETURN, T.LET, T.FOR, T.IF, T.READ, T.WRITE, T.SETPARAM, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            if el ^ T.RETURN:
                p >> T.RETURN
                ret = p.expr()
                p >> T.SEMI
                statements.append(Return(ret))
            else:
                more = p.stmts()
                statements += more

        return statements

    def stmts(p, more=True):
        elements = []
        while el := p > {T.MUTATION, T.LET, T.FOR, T.IF, T.READ, T.WRITE, T.SETPARAM, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRING, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            if el ^ T.FOR:
                elements.append(p.forloop())
            elif el ^ T.IF:
                elements.append(p.branch())
            elif el ^ T.READ or el ^ T.WRITE or el ^ T.SETPARAM:
                elements.append(p.call())
                p >> T.SEMI
            elif el ^ T.IME or el ^ T.MUTATION or el ^ T.BROJ or el ^ T.STRING or el ^ T.TRUE or el ^ T.FALSE or el ^ T.MINUS or el ^ T.NOT or el ^ T.OTV or el ^ T.STRINGTYPE or el ^ T.NUMBER or el ^ T.BOOL or el ^ T.FUNGUS or el ^ T.TREE or el ^ T.EDIBILITY or el ^ T.DNA or el ^ T.DATETIME or el ^ T.DEADLY or el ^ T.TOXIC1 or el ^ T.TOXIC2 or el ^ T.EDIBLE or el ^ T.DATUM or el ^ T.LUGL:
                elements.append(p.expr()) #tu su ubačeni i call za user-fun i naredbe pridruživanja; disambiguacija se događa tek u expr() (ne može prije jer LL(1))
                p >> T.SEMI
            elif el ^ T.LET:
                elements.append(p.decl())
                p >> T.SEMI
            if not more:
                break
        # ne hendlamo početni token za `asgn` ovdje jer je on početni i za `expr`; općenito, smatrat ćemo da su i dodjele izrazi, iako nama semantički nisu
        # i to će se razriješiti u odgovarajućoj funkciji
        if not more and len(elements) == 0:
            raise p.greška('Očekivana jedna naredba')
        return elements
    
    def stmts2(p, more=True):
        statements = []
        while p > {T.MUTATION, T.LET, T.CONTINUE, T.BREAK, T.FOR, T.IF, T.READ, T.WRITE, T.SETPARAM, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            if el := p >= {T.CONTINUE, T.BREAK}:
                p >> T.SEMI
                statements.append(el)
            else:
                statements += p.stmts(more)

        return statements
        
    
    # forloop -> FOR IME LVIT stmt2* DVIT | FOR IME stmt2
    def forloop(p):
        p >> T.FOR
        var = p >> T.IME
        if not is_in_symtable(var):
            raise p.greška('Varijabla ' + var.sadržaj + ' nije definirana')
        idx, symtab = get_symtab(var)
        if p >= T.LVIT:
            stmts = p.stmts2()
            p >> T.DVIT
            return ForLoop(var, stmts)
        else:
            stmt = p.stmts2(False)
            return ForLoop(var, stmt)
        
# branch -> IF OTV expr ZATV LVIT stmt* DVIT | IF OTV expr ZATV LVIT stmt* DVIT ELSE LVIT stmt* DVIT
    def branch(p):
        p >> T.IF
        p >> T.OTV
        test = p.expr()
        if not is_boolean(test):
            raise SemantičkaGreška('Uvjeti za grananje moraju biti bool izrazi')
        p >> T.ZATV
        p >> T.LVIT
        branch1 = p.stmts()
        p >> T.DVIT
        if p >= T.ELSE:
            p >> T.LVIT
            branch2 = p.stmts()
            p >> T.DVIT
            return ComplexBranch(test, branch1, branch2)
        else:
            return SimpleBranch(test, branch1)
        
        # call -> (IME|READ|WRITE) OTV args? ZATV
        # setparam_call -> SETPARAM OTV setargs ZATV
# setargs -> (IME COLON expr COMMA)+ IME COLON expr | IME COLON expr
    def call(p):
        fun = None
        if fun := p >= T.IME:
            if not is_function_defined(fun): # koristimo ovu zasebnu funkciju za funkcijske simbole jer oni moraju biti samo u globalnom scopeu
                raise SemantičkaGreška('Funkcija ' + fun.sadržaj + ' nije definirana')
            #idx, symtab = get_symtab(fun)
            #if not symtab[fun] ^ Function:
                #raise p.greška('Očekivana funkcija za poziv')
            #fun = symtab[fun]
            fun = rt.funtab[fun]
        elif fun := p >= T.SETPARAM:
            p >> T.OTV
            args = {}
            while p >= T.COMMA:
                key = p >> T.IME
                if key in args:
                    raise SemantičkaGreška('Već ste naveli vrijednost parametra ' + key.sadržaj)
                p >> T.COLON
                val = p.expr()
                args[key] = val
            p >> T.ZATV
            return Call(fun, args)
        else: 
            fun = p >> {T.READ, T.WRITE}
        
        p >> T.OTV
        args = []
        if p > {T.MUTATION, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            args = p.args()
        fun.validate_call(*args)
        p >> T.ZATV
        return Call(fun, args)
    
# expr -> expr0 ASGN expr | expr0
# expr0 -> cross UPIT expr0 COLON expr | cross
# cross -> cross CROSSING sel | sel
# sel -> sel SELECTION | mut
# mut -> MUTATION mut | expr2
# expr2 -> expr2 OR expr3 | expr3

    def expr(p):
        left = p.expr0()
        if p >= T.ASGN:
            # imamo pridruživanje, pa lijevo smiju biti samo: imena, dot-liste
            print(type(left))
            if not (left ^ T.IME or left ^ DotList):
                raise SemantičkaGreška('Pridruživati možete samo varijabli ili nekom članu složenijeg objekta')
            right = p.expr()
            if right ^ Assignment:
                raise SintaksnaGreška('Ulančavana pridruživanja nisu legalna') # ?
            return Assignment(left, right)
        return left

    def expr0(p):
        left = p.cross()
        if p >= T.UPIT:
            middle = p.expr0()
            if not is_boolean(middle):
                raise SemantičkaGreška('Prvi izraz ternarnog operatora mora biti upit (boolean)')
            p >> T.COLON
            right = p.expr0()
            if left ^ Assignment or middle ^ Assignment or right ^ Assignment:
                raise GreškaPridruživanja
            return Ternary(left, middle, right)
        else:
            return left
        #TODO: trebamo li dozvoliti višestruka pridruživanja oblika a=b=c=d? To bi mogli posebnim pravilom za stmt...
    def cross(p):
        tree = p.sel()
        while op := p >= T.CROSSING:
            tree = Binary(op, tree, p.sel())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            #if not listcheck_fungus(tree.left, tree.right):
            if not is_fungus(tree.left) or not is_fungus(tree.right): # ovdje ne želimo detaljnije rekurzivne provjere kompatibilnosti listi jer
                # je ponašanje ovog operatora složeno i parametrizirano runtime parametrima koje ne sada ne znamo
                raise SemantičkaGreška('Samo se liste gljiva mogu križati')
        return tree
    
    def sel(p):
        tree = p.mut()
        if op := p >= T.SELECTION:
            if not is_fungus(tree):
                raise SemantičkaGreška('Samo se liste gljiva mogu selektirati')
            return Unary(op, tree)
        return tree
    
    def mut(p):
        if op := p >= T.MUTATION:
            tmp = p.mut()
            if not is_fungus(tmp):
                raise SemantičkaGreška('Samo se gljive ili njihove liste mogu mutirati')
            return Unary(op, p.mut())
        return p.expr2()
        
    def expr2(p):
        tree = p.expr3()
        while op := p >= T.OR:
            tree = Binary(op, tree, p.expr3())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            if not is_boolean(tree.left) or not is_boolean(tree.right):
                raise SemantičkaGreška('Logičke operacije podržane samo nad boolean izrazima/vrijednostima')
            if is_list(tree.left) or is_list(tree.right):
                raise SemantičkaGreška('Liste ne mogu biti u logičkim izrazima') 

        return tree
    
# expr3 -> expr3 AND expr5 | expr5
# expr5 -> expr5 EQ expr6 | expr5 NEQ expr6 | expr6
# expr6 -> expr6 LT expr4 | expr6 LE expr4 | expr6 GT expr4 | expr6 GE expr4 | expr4
# expr4 -> (term PLUS)+ term | (term MINUS)+ term | term
    
    def expr3(p):
        tree = p.expr5()
        while op := p >= T.AND:
            tree = Binary(op, tree, p.expr5())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            if not is_boolean(tree.left) or not is_boolean(tree.right):
                raise SemantičkaGreška('Logičke operacije podržane samo nad boolean izrazima/vrijednostima')
            if is_list(tree.left) or is_list(tree.right):
                raise SemantičkaGreška('Liste ne mogu biti u logičkim izrazima') 
        return tree
    
    def expr5(p):
        tree = p.expr6()
        while op := p >= {T.EQ, T.NEQ}:
            tree = Binary(op, tree, p.expr6())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            #if is_list(tree.left) or is_list(tree.right):
                #if not listcheck_bool(tree.left, tree.right):
                    #raise SemantičkaGreška('Lijeva i desna lista nisu kompatibilne za test (ne)jednakosti')
        
            
        return tree
    
    def expr6(p):
        tree = p.expr4()
        while op := p >= {T.LT, T.LE, T.GT, T.GE}:
            tree = Binary(op, tree, p.expr4())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            if not is_arithmetic(tree.left) and not is_arithmetic(tree.right):
                raise SemantičkaGreška('<, >, <= i >= su upotrebljivi samo nad brojevnim izrazima/vrijednostima')
            if is_list(tree.left) or is_list(tree.right):
                raise SemantičkaGreška('Liste se ne mogu uspoređivati') #TODO: ovo bi mogli dopustiti, ali onda kompliciramo rad s rezultatom koji
            # je također lista... ili bi trebao biti samo jedan bool rezultat?
        return tree
    
    def expr4(p):
        terms = [[T.PLUS, p.term()]]
        arithmetic = True
        stringetic = True
        tlen = terms[-1][1].get_list_length()
        while op := p >= {T.PLUS, T.MINUS}:
            if terms[-1][1] ^ Assignment:
                raise GreškaPridruživanja
            if not arithmetic and not stringetic:
                raise SemantičkaGreška('+ i - dozvoljeno samo nad brojevima i stringovima')
            if not is_arithmetic(terms[-1][1]):
                if not stringetic:
                    raise SemantičkaGreška('Aritmetičke operacije s brojem mogu biti samo s drugim brojem')
                arithmetic = False
            if not is_stringetic(terms[-1][1]):
                if not arithmetic:
                    raise SemantičkaGreška('Konkatenacija stringa moguća samo s drugim stringom')
                stringetic = False
            if op ^ T.MINUS:
                if not arithmetic:
                    raise SemantičkaGreška('Oduzimanje nije podržano nad stringovima')
                stringetic = False
            if terms[-1][1] ^ List:
                if tlen != terms[-1][1].get_list_length():
                    raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
            terms.append([op, p.term()])
        if len(terms) == 1:
            return terms[0][1]
        else: #TODO: bilo bi lijepo kada ne bi morali ponoviti cijeli ovaj blok ovdje... do while?
            if terms[-1][1] ^ Assignment:
                raise GreškaPridruživanja
            if not arithmetic and not stringetic:
                raise SemantičkaGreška('+ i - dozvoljeno samo nad brojevima i stringovima')
            if not is_arithmetic(terms[-1][1]):
                if not stringetic:
                    raise SemantičkaGreška('Aritmetičke operacije s brojem mogu biti samo s drugim brojem')
                arithmetic = False
            if not is_stringetic(terms[-1][1]):
                if not arithmetic:
                    raise SemantičkaGreška('Konkatenacija stringa moguća samo s drugim stringom')
                stringetic = False
            if op ^ T.MINUS:
                if not arithmetic:
                    raise SemantičkaGreška('Oduzimanje nije podržano nad stringovima')
                stringetic = False
            if terms[-1][1] ^ List:
                if tlen != terms[-1][1].get_list_length():
                    raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
        if not listcheck_numberunits(*[el[1].vrijednost() for el in terms]): # ovdje ne moramo provjeravati ništa osim pravilnosti lista (rekurzivno), jer je kod iznad
            # već provjerio sve što se tiče dopuštenih operacija, što uključuje i korektnost jedinica
            raise SemantičkaGreška('Nekompatibilne liste za + i -')
        return Nary(terms)
    
    def term(p):
        facts = [[T.PUTA, p.fact()]]
        flen = facts[-1][1].get_list_length()
        while op := p >= {T.PUTA, T.DIV}:
            if not is_arithmetic(facts[-1][1]):
                raise SemantičkaGreška('Množenje i dijeljenje moguće samo s brojevnim operandima/listama')
            left = facts[-1][1]
            facts.append([op, p.fact()])
            right = facts[1][1]
            #if left ^ Number and left.unit and not (right ^ Number and not right.unit) or right ^ Number and right.unit and not (left ^ Number and not left.unit):
             #   raise SemantičkaGreška('Množenje/dijeljenje dimenzionalnom veličinom je dozvoljeno samo s (bezdimenzionalnim) skalarom')
            if facts[-1][1] ^ List:
                if facts[-1][1].get_list_length() != flen:
                    raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
                # ako se liste pojavljuju u množenju/dijeljenju, to je dopustivo i u proizvoljnoj kombinaciji sa skalarima, s prirodnom
                # (lijevo asociranom) interpretacijom, ali sve liste moraju biti jednake duljine ("broadcasting")
        if len(facts) == 1:
            return facts[0][1]
        if not listcheck_number(*[el[1].vrijednost() for el in facts]):
            raise SemantičkaGreška('Nekompatibilne liste brojeva za * i /')
        if not units_check(*[el[1].vrijednost() for el in facts]):
            raise SemantičkaGreška('Množenje/dijeljenje dimenzionalnom veličinom je dozvoljeno samo s (bezdimenzionalnim) skalarom')
        return Nary(facts)
    
    def fact(p):
        bots = [p.bot()]
        while p >= T.DOT: 
            bots.append(p.bot(True))
        if len(bots) > 1:
            if not bots[0] ^ ConstructorCall and not bots[0] ^ T.IME:
                raise SemantičkaGreška('Početak liste s točkama mora biti konstruiran objekt ili ime')
            for item in bots[1:]:
                if not item ^ T.IME:
                    raise SemantičkaGreška('Samo imena svojstava smiju biti između točaka')
        return DotList.ili_samo(bots)
    

    # cons -> type OTV args? ZATV   # konstruktori za builtin tipove
    # type -> (STRINGTYPE | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DNA | DATETIME)
    def bot(p,dotted=False):
        if var := p > T.IME:
            if dotted:
                p >> T.IME
                return var # ovo je ime nekog svojstva, ne možemo dalje analizirati
            if is_in_symtable(var):# inače je čisto pridruživanje varijable ili čisto pojavljivanje varijable (po mogućnosti unutar složenijeg izraza)
                p >> T.IME # pojedi, inače ne jer call() mora vidjeti ime!
                return var
            # ovo mora biti poziv funkcije 'var'
            if var in rt.funtab:
                return p.call()
            else:
                print('ime je sada=',var)
                for whatever in rt.symtab[-1]:
                    print(whatever)
                raise p.greška('Ime ' + var.sadržaj + ' nije viđeno do sada')   
        elif p > {T.READ, T.WRITE, T.SETPARAM}:
            return p.call()
        elif num := p >= T.BROJ:
            unit = p >= {T.MILIGRAM, T.GRAM, T.KILOGRAM}
            return Number(num.vrijednost(), unit)
        elif literal := p >= {T.STRING, T.TRUE, T.FALSE}:
            return Literal(literal)
        elif op := p >= {T.MINUS, T.NOT}:
            below = p.bot()
            if op ^ T.MINUS and not is_arithmetic(below):
                raise SemantičkaGreška('Negirati se mogu samo brojevni izrazi')
            if op ^ T.NOT and not is_boolean(below):
                raise SemantičkaGreška('Logička negacija moguća samo na bool izrazima')
            return Unary(op, below)
        elif p >= T.OTV:
            subexpr = p.expr()
            p >> T.ZATV
            return subexpr
        elif p > {T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME}:
            return p.cons()
        elif p > T.DATUM:
            return p.datespec()
        elif p > T.LUGL:
            return p.list()
        else:
            return p.edb()
# decl -> LET IME | LET asgn
# cons -> type OTV args? ZATV | DNA LUGL params DUGL | DNA OTV IME ZATV 
    def cons(p):
        type = p >> {T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME}
        p >> T.OTV
        if type ^ T.DNA: # poseban slučaj za konstrukciju DNA: može kao DNA(ATCGGA) ili kao DNA([A,T,C,G,G,A])
            if p >= T.LUGL:
                bases = p.params()
                # validiraj da su imena samo 'A', 'T', 'C' ili 'G'
                for base in bases:
                    if base.sadržaj not in {'A', 'T', 'C', 'G'}:
                        raise SintaksnaGreška('Netočan format DNA: očekivani nukleotidi iz {A,T,C,G}')
                p >> T.DUGL
                p >> T.ZATV
                values = [base.sadržaj for base in bases]
                return DNA(values)
            elif bases := p >> T.IME:
                for base in bases.sadržaj:
                    if base not in {'A', 'T', 'C', 'G'}:
                        raise SintaksnaGreška('Netočan format DNA: očekivani nukleotidi iz {A,T,C,G}')
                p >> T.ZATV
                return DNA(bases)
        args = []
        if p > {T.MUTATION, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            args = p.args()
        p >> T.ZATV
        type.validate_call(*args) # pokušamo statički što više provjeriti
        return ConstructorCall(type, args)
    
    def datespec(p):
        date = p >> T.DATUM
        #date.validiraj() # je li ovo ok datum, čisto sintaktički?
        date = date.vrijednost()
        minutes = 0
        seconds = 0
        if hour := p >= T.BROJ:
            p >> T.COLON
            minutes = p >> T.BROJ
            if p >= T.COLON:
                seconds = p >> T.BROJ
            tmp = DateTime(date, int(hour.sadržaj), int(minutes.sadržaj), int(seconds.sadržaj))
            tmp.validate()
            return tmp
        else:
            tmp = Date(date)
            tmp.validate()
            return tmp

    def list(p):
        p >> T.LUGL
        #if not p > {T.MUTATION, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
        if not (p > {T.MUTATION, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}):
            return List([])
        exprs = [p.expr()]
        while p >= T.COMMA: exprs.append(p.expr())
        p >> T.DUGL
        return List(exprs)
    
    def edb(p):
        kind = p >> {T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE}
        return Edibility(kind)

    def decl(p):
        p >> T.LET
        var = p >> T.IME
        if is_in_symtable(var):
            idx, symtab = get_symtab(var)
            if idx == len(rt.symtab) - 1: # ne skrivamo vanjsku varijablu već je redeklariramo unutar istog scopea, što ne dozvoljavamo
                raise p.greška('Varijabla ' + var.sadržaj + ' je već deklarirana u ovom dosegu')
        rt.symtab[-1][var] = var

        if p >= T.ASGN:
            return Assignment(var, p.expr())
        else:
            return Declaration(var)

    def args(p):
        exprs = [p.expr()]
        while p >= T.COMMA: exprs.append(p.expr())
        return exprs

        


class Povratak(NelokalnaKontrolaToka): pass
class Nastavak(NelokalnaKontrolaToka): pass
class Prekid(NelokalnaKontrolaToka): pass

class Program(AST):
    statements: ...
    functions: ...

    def izvrši(self):
        rt.symtab.pop() # očisti stog
        rt.symtab = list()
        rt.symtab.append(Memorija())
        rt.okolina = rt.symtab # tu držimo vrijednosti vidljivih varijabli; na početku su to samo globalne, a svaki pojedini poziv stvara okvir tj. nadodaje
        # stvari koje onda skida kada završi s izvršavanjem pozvane funkcije
        rt.params = Memorija() # tu spremamo parametre postavljene sa setParams; ovdje želimo postaviti neke smislene defaulte koje koriste genetski
        # operatori
        rt.params['preferparents'] = (0,0)
        rt.params['dist'] = 'gauss'
        rt.params['mean'] = 0.0
        rt.params['stddev'] = 0.2

        for stmt in self.statements:
            stmt.izvrši()

class Function(AST):
    name: ...
    parameter_names: ...
    body: ...

    def validate_call(self, *args):
        if len(self.parameter_names) != len(args):
            raise SemantičkaGreška('Broj argumenata kod poziva funkcije' + self.name.sadržaj + ' treba biti ' + len(self.parameter_names))

    def izvrši(self):
        # ovo je općenit mehanizam za pozivanje funkcija koji simulira sistemski stog (call stack) i stoga omogućuje sve oblike rekurzije, 
        # samo što mi ne podržavamo poziv funkcije koja još nije do kraja definirana zbog jednoprolaznosti parsera (dakle, nije podržavana rekurzija u
        # punom smislu)
        for stmt in self.body:
            stmt.izvrši()

class ForLoop(AST):
    loop_variable: ...
    body_statements: ...

    def izvrši(self):
        idx, var = get_symtab(self.loop_variable)
        if not var ^ Number:
            raise SemantičkaGreška('Varijabla u for petlji mora biti numerička')
        while self.loop_variable.vrijednost() != 0:
            try:
                self.body_statements.izvrši()
            except Prekid:
                break
            except Nastavak: pass
            rt.okolina[idx][self.loop_variable] -= 1 # ovo je default petlja; mogli bismo dodati i još neke, ali čak i ovakva implementacija
            # dozvoljava da korisnik mijenja varijablu i utječe na ponašanje petlje tijekom njena izvođenja

class SimpleBranch(AST):
    test: ...
    branch1_statements: ...

    def izvrši(self):
        if self.test.vrijednost():
            self.branch1_statements.izvrši()

class ComplexBranch(SimpleBranch):
    branch2_statements: ...

    def izvrši(self):
        if self.test.vrijednost():
            self.branch1_statements.izvrši()
        else:
            self.branch2_statements.izvrši()

class Call(AST):
    function: ...
    arguments: ...

    def vrijednost(self):
        if self.function ^ T.SETPARAM or self.function ^ T.READ or self.function ^ T.WRITE: # builtins
            return self.function.izvrši(*self.arguments)
        
        rt.okolina.append(Memorija())
        i = 0
        for param in rt.funtab[self.function].parameter_names:
            rt.okolina[-1][param] = self.arguments[i].vrijednost()
            i += 1

        retval = None
        try:
            rt.funtab[self.function].izvrši()
        except Povratak as ex:
            retval = ex.preneseno
        
        rt.okolina.pop()
        return retval

    def get_list_length(self):
        return None
    
class Return(AST):
    expression: ...

    def izvrši(self):
        raise NelokalnaKontrolaToka(self.expression.vrijednost())

class Ternary(AST):
    left: ...
    middle: ...
    right: ...
    
    def izvrši(self):
        self.vrijednost()

    def vrijednost(self):
        if self.left.vrijednost():
            return self.middle.vrijednost()
        else:
            return self.right.vrijednost()

class Binary(AST):
    op: ...
    left: ...
    right: ...

    def izvrši(self):
        self.vrijednost()

    def vrijednost(self):
        if self.op ^ T.CROSSING:
            children = []
            if rt.params['dist'] == 'gauss': # TODO:preostale mogućnosti
                if self.left ^ List and self.right ^ List and self.left.get_list_length() == self.right.get_list_length():
                    children = [onecross(left, right) for left,right in zip(self.left, self.right)]
                elif self.left ^ List and self.right ^ List and len(rt.params['preferparents']) != 0:
                    prefs = rt.params['preferparents']
                    children = [onecross(self.left[prefs[0]], self.right[prefs[1]])]
        elif self.op ^ T.AND:
            # nema listi
            left = self.left.vrijednost()
            if type(left) == bool and not left:
                return False # short circuiting
            right = self.right.vrijednost()
            if type(left) != bool or type(right) != bool:
                raise SemantičkaGreška('Logički operatori su legalni samo nad bool izrazima')
            return left and right
        elif self.op ^ T.OR:
            left = self.left.vrijednost()
            if type(left) == bool and left:
                return True
            right = self.right.vrijednost()
            if type(left) != bool or type(right) != bool:
                raise SemantičkaGreška('Logički operatori su legalni samo nad bool izrazima')
            return left or right
        elif self.op ^ T.EQ:
            left = self.left.vrijednost()
            right = self.right.vrijednost()
            if type(left) == type(right) and type(left) != list:
                return left == right
            elif type(left) == type(right): # riječ je o listi
                if len(left) != len(right):
                    return False
                # moramo rekurzivno dalje
                res = True
                for op1,op2 in zip(left, right):
                    res = res and eq_recursive(op1, op2)
                return res
            return False
        elif self.op ^ T.NEQ:
            left = self.left.vrijednost()
            right = self.right.vrijednost()
            if type(left) == type(right) and type(left) != list:
                return left != right
            elif type(left) == type(right): # riječ je o listi
                if len(left) != len(right):
                    return True
                # moramo rekurzivno dalje
                res = True
                for op1,op2 in zip(left, right):
                    res = res and not eq_recursive(op1, op2)
                return res
            return True
        elif self.op ^ T.GE:
            left = self.left.vrijednost()
            right = self.right.vrijednost()
            if left ^ Number and right ^ Number:
                return left >= right
            raise SemantičkaGreška('Samo se brojevi mogu uspoređivati sa <, >, <=, >=')
        elif self.op ^ T.GT:
            left = self.left.vrijednost()
            right = self.right.vrijednost()
            if left ^ Number and right ^ Number:
                return left > right
            raise SemantičkaGreška('Samo se brojevi mogu uspoređivati sa <, >, <=, >=')
        elif self.op ^ T.LE:
            left = self.left.vrijednost()
            right = self.right.vrijednost()
            if left ^ Number and right ^ Number:
                return left <= right
            raise SemantičkaGreška('Samo se brojevi mogu uspoređivati sa <, >, <=, >=')
        elif self.op ^ T.LT:
            left = self.left.vrijednost()
            right = self.right.vrijednost()
            if left ^ Number and right ^ Number:
                return left < right
            raise SemantičkaGreška('Samo se brojevi mogu uspoređivati sa <, >, <=, >=')
                    

    def get_list_length(self):
        return self.left.get_list_length()

def eq_recursive(op1, op2):
    left = op1.vrijednost()
    right = op2.vrijednost()
    if type(left) == type(right) and type(left) != list:
        return left == right 
    elif type(left) == type(right):
        if len(left) != len(right):
            return False
        res = True
        for n1,n2 in zip(left, right):
            res = res and eq_recursive(n1, n2)
        return res
    return False

class Unary(AST):
    op: ...
    child: ...

    def izvrši(self):
        self.vrijednost()

    def vrijednost(self):
        if self.op ^ T.MUTATION: pass #TODO
        elif self.op ^ T.SELECTION: pass #TODO
        elif self.op ^ T.MINUS:
            tmp = self.child.vrijednost()
            if tmp ^ Number:
                tmp.value = -tmp.value
                return tmp
            if type(tmp) == list:
                for el in tmp:
                    new = Unary(self.op, el)
                    el = new.vrijednost() # rekurzija, mijenja listu
                return tmp
            raise SemantičkaGreška('Negirati se mogu samo numeričke liste ili brojevi')
        elif self.op ^ T.NOT:
            tmp = self.child.vrijednost()
            if type(tmp) == bool:
                return not tmp
            if type(tmp) == list:
                for el in tmp:
                    new = Unary(self.op, el)
                    el = new.vrijednost()
                return tmp


    def get_list_length(self):
        return self.child.get_list_length()

def unit_conv(val, src, dest):
    if not dest:
        return val
    if type(src) == type(dest):
        return val
    if src ^ T.MILIGRAM and dest ^ T.GRAM:
        return val / 1000
    if src ^ T.GRAM and dest ^ T.MILIGRAM:
        return val * 1000
    if src ^ T.KILOGRAM and dest ^ T.GRAM:
        return val * 1000
    if src ^ T.GRAM and dest ^ T.KILOGRAM:
        return val / 1000
    if src ^ T.KILOGRAM and dest ^ T.MILIGRAM:
        return val * 1e6
    if src ^ T.MILIGRAM and dest ^ T.KILOGRAM:
        return val / 1e6

class Nary(AST):
    pairs: ... # (op,expr) pairs

    def izvrši(self):
        self.vrijednost()

    def get_list_length(self):
        return self.pairs[0][1].get_list_length()
    
    def vrijednost(self):
        accum = copy.deepcopy(self.pairs[0][1].vrijednost())
        unit = None if not accum ^ Number else accum.unit
        for op,val in self.pairs[1:]:
            if op ^ T.MINUS:
                tmp = val.vrijednost()
                if type(tmp) == list ^ type(accum) == list:
                    raise SemantičkaGreška('Lista se može oduzimati samo s listom')
                if type(accum) == list:
                    if len(tmp) != len(accum):
                        raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
                    for i in range(len(accum)):
                        el1 = accum[i]
                        el2 = tmp[i]
                        new = Nary([[op,el1], [op,el2]])
                        accum[i] = new.vrijednost() # rekurzija, mijenja accum
                elif accum ^ Number and tmp ^ Number:
                    if unit and not tmp.unit or not unit and tmp.unit:
                        raise SemantičkaGreška('Nije navedena jedinica pri oduzimanju')
                    #accum.value -= unit_conv(tmp.value, tmp.unit, unit)
                    accum = accum - tmp
                else:
                    raise SemantičkaGreška('Nekompatibilni operandi oduzimanja')
        
            elif op ^ T.PLUS:
                tmp = val.vrijednost()
                if type(tmp) == list ^ type(accum) == list:
                    raise SemantičkaGreška('Lista se može zbrajati samo s listom')
                if type(accum) == list:
                    if len(tmp) != len(accum):
                        raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
                    for i in range(len(accum)):
                        el1 = accum[i]
                        el2 = tmp[i]
                        new = Nary([[op,el1], [op,el2]])
                        accum[i] = new.vrijednost() # rekurzija, mijenja accum
                elif accum ^ Number and tmp ^ Number or type(accum) == type(tmp) == str:
                    if unit and not tmp.unit or not unit and tmp.unit:
                        raise SemantičkaGreška('Nije navedena jedinica pri zbrajanju')
                    #accum.value += unit_conv(tmp.value, tmp.unit, unit)
                    accum = accum + tmp
                else:
                    raise SemantičkaGreška('Nekompatibilni operandi zbrajanja')

            elif op ^ T.MUL:
                tmp = val.vrijednost()
                if type(tmp) == list ^ type(accum) == list:
                    raise SemantičkaGreška('Lista se može množiti samo s listom')
                if type(accum) == list:
                    if len(tmp) != len(accum):
                        raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
                    for i in range(len(accum)):
                        el1 = accum[i]
                        el2 = tmp[i]
                        new = Nary([[op,el1], [op,el2]])
                        accum[i] = new.vrijednost() # rekurzija, mijenja accum
                elif accum ^ Number and tmp ^ Number:
                    if unit and tmp.unit:
                        raise SemantičkaGreška('Nije moguće množiti dvije dimenzionalne veličine')
                    elif tmp.unit:
                        accum.unit = unit = tmp.unit
                    #accum.value *= unit_conv(tmp.value, tmp.unit, unit)
                    accum = accum * tmp
                else:
                    raise SemantičkaGreška('Nekompatibilni operandi množenja')
        
            elif op ^ T.DIV:
                tmp = val.vrijednost()
                if type(tmp) == list ^ type(accum) == list:
                    raise SemantičkaGreška('Lista se može dijeliti samo s listom')
                if type(accum) == list:
                    if len(tmp) != len(accum):
                        raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
                    for i in range(len(accum)):
                        el1 = accum[i]
                        el2 = tmp[i]
                        new = Nary([[op,el1], [op,el2]])
                        accum[i] = new.vrijednost() # rekurzija, mijenja accum
                elif accum ^ Number and  tmp ^ Number:
                    if unit and tmp.unit:
                        raise SemantičkaGreška('Nije moguće dijeliti dvije dimenzionalne veličine')
                    elif tmp.unit:
                        accum.unit = unit = tmp.unit
                    #accum.value /= unit_conv(tmp.value, tmp.unit, unit)
                    accum = accum / tmp
                else:
                    raise SemantičkaGreška('Nekompatibilni operandi množenja')
                
        return accum

class DotList(AST):
    elements: ...
#SPECIES, GENUS, FAMILY, ORDER, CLASS, PHYLUM, KINGDOM = 'spec', 'gen', 'fam', 'ord', 'class', 'phyl', 'king'
    def vrijednost(self):
        obj = self.elements[0].vrijednost() # moramo pristupati kroz neki objekt: Fungus ili Tree
        ret = None
        if obj ^ Fungus:
            if self.elements[1].sadržaj == 'name':
                ret = DotList.ili_samo([obj.name, *self.elements[2:]])
            elif self.elements[1].sadržaj == 'latin':
                ret = DotList.ili_samo([obj.latin, *self.elements[2:]])
            elif self.elements[1].sadržaj == 'dna':
                ret = DotList.ili_samo([obj.dna, *self.elements[2:]])
            elif self.elements[1].sadržaj == 'taxonomy':
                ret = DotList.ili_samo([obj.taxonomy, *self.elements[2:]])
            elif self.elements[1].sadržaj == 'edibility':
                ret = DotList.ili_samo([obj.edibility, *self.elements[2:]])
            elif self.elements[1].sadržaj == 'timestamp':
                ret = DotList.ili_samo([obj.timestamp, *self.elements[2:]])
            else:
                raise SemantičkaGreška('Nepoznat atribut Fungus objekta: ' + self.elements[1].sadržaj)
            if ret ^ DotList:
                return ret.vrijednost()
        elif obj ^ Tree:
            if self.elements[1].sadržaj == 'spec':
                return obj.spec
            elif self.elements[1].sadržaj == 'gen':
                return obj.gen
            elif self.elements[1].sadržaj == 'fam':
                return obj.fam
            elif self.elements[1].sadržaj == 'ord':
                return obj.ord
            elif self.elements[1].sadržaj == 'class':
                return obj.klasa
            elif self.elements[1].sadržaj == 'phyl':
                return obj.phyl
            elif self.elements[1].sadržaj == 'king':
                return obj.king
            else:
                raise SemantičkaGreška('Nepostojeći element taksonomije u specifikaciji')    
        else:
            raise SemantičkaGreška('Sa točkom se može pristupati samo svojstvima Fungus i Tree objekata')

    def get_list_length(self):
        return None

class Assignment(AST):
    variable: ...# ovo ustvari ne mora samo biti varijabla već i dot-lista
    expression: ...

    def izvrši(self):
        # želimo drukčija ponašanja glede kopiranja objekata; najveći objekti se kopiraju samo po referenci, ali za ostale želimo potpunu (duboku) kopiju
        if self.variable ^ T.IME:
            tmp = self.expression.vrijednost()
            if tmp ^ Fungus or tmp ^ DNA:
                rt.okolina[-1][self.variable] = self.expression.vrijednost()
            else:
                rt.okolina[-1][self.variable] = copy.deepcopy(self.expression.vrijednost())
        elif self.variable ^ DotList:
            # dopuštamo izmjenu samo taksonomija...
            dotlist = self.variable
            var = rt.okolina[-1][dotlist.elements[0]]
            if not dotlist.elements[0].vrijednost() ^ Tree:
                raise SemantičkaGreška('Samo taksonomije mogu biti mijenjane sa . listama')
            if len(dotlist.elements) != 2:
                raise SemantičkaGreška('Nepostojeći član')
            if dotlist.elements[1].sadržaj == 'spec':
                var.species = self.expression.vrijednost()
            elif dotlist.elements[1].sadržaj == 'gen':
                var.genus = self.expression.vrijednost()
            elif dotlist.elements[1].sadržaj == 'fam':
                var.family = self.expression.vrijednost()
            elif dotlist.elements[1].sadržaj == 'ord':
                var.order = self.expression.vrijednost()
            elif dotlist.elements[1].sadržaj == 'class':
                var.klasa = self.expression.vrijednost()
            elif dotlist.elements[1].sadržaj == 'phyl':
                var.phylum = self.expression.vrijednost()
            elif dotlist.elements[1].sadržaj == 'king':
                var.kingdom = self.expression.vrijednost()
            else:
                raise SemantičkaGreška('Ilegalni element taksonomije')

class Number(AST):
    value: ...
    unit: ...

    def __add__(self, other):
        val = self.value + unit_conv(other.value, other.unit, self.unit)
        return Number(val, self.unit)
    
    def __sub__(self, other):
        val = self.value - unit_conv(other.value, other.unit, self.unit)
        return Number(val, self.unit)
    
    def __mul__(self, other):
        val = self.value * unit_conv(other.value, other.unit, self.unit)
        return Number(val, self.unit)
    
    def __truediv__(self, other):
        val = self.value / unit_conv(other.value, other.unit, self.unit)
        return Number(val, self.unit)
    
    def __lt__(self, other):
        if self.unit ^ other.unit:
            raise SemantičkaGreška('Usporedba dimenzionalne i nedimenzionalne veličine')
        val = unit_conv(other.value, other.unit, self.unit)
        return self.value < val
    
    def __gt__(self, other):
        if self.unit ^ other.unit:
            raise SemantičkaGreška('Usporedba dimenzionalne i nedimenzionalne veličine')
        val = unit_conv(other.value, other.unit, self.unit)
        return self.value > val
    
    def __le__(self, other):
        if self.unit ^ other.unit:
            raise SemantičkaGreška('Usporedba dimenzionalne i nedimenzionalne veličine')
        val = unit_conv(other.value, other.unit, self.unit)
        return self.value <= val
    
    def __eq__(self, other):
        if self.unit ^ other.unit:
            raise SemantičkaGreška('Usporedba dimenzionalne i nedimenzionalne veličine')
        val = unit_conv(other.value, other.unit, self.unit)
        return self.value == val
    
    def __ne__(self, other):
        if self.unit ^ other.unit:
            raise SemantičkaGreška('Usporedba dimenzionalne i nedimenzionalne veličine')
        val = unit_conv(other.value, other.unit, self.unit)
        return self.value != val


    def izvrši(self):
        raise SemantičkaGreška('Ovo nije naredba')

    def vrijednost(self):
        return self # ovo treba biti dno što se tiče brojeva; value je uvijek konkretan float ovdje

    def get_list_length(self):
        return None
    
    def to_string(self):
        tmp = str(self.value)
        if self.unit:
            tmp += ' ' + self.unit.sadržaj
        return tmp

class Literal(AST):
    value: ...

    def izvrši(self):
        raise SemantičkaGreška('Ovo nije naredba')

    def vrijednost(self):
        if self.value ^ T.STRING:
            return self.value.vrijednost()
        elif type(self.value) == str:
            return self.value
        elif self.value ^ T.TRUE:
            return True
        elif self.value ^ T.FALSE:
            return False
        raise SemantičkaGreška('Nemoguć literal')

    def get_list_length(self):
        return None
        
    def to_string(self):
        return self.value.vrijednost()
    

class ConstructorCall(AST):
    type: ...
    arguments: ...

    def izvrši(self):
        self.vrijednost()

    def vrijednost(self):
        true = True
        false = False
                        
        if self.type ^ T.BOOL:
            if len(self.arguments) != 1:
                raise SemantičkaGreška('Konstruktor bool-a prima jedan argument')
            arg = self.arguments[0].vrijednost()
            if type(arg) == bool:
                if arg:
                    return true
                else:
                    return false
            elif arg ^ Number: # konverzija Number->Bool: False akko 0
                if arg.value == 0:
                    return false
                else:
                    return true
            elif type(arg) == str: # konverzija String->Bool: False akko duljine 0
                if len(arg) == 0:
                    return false
                else:
                    return true
            elif arg ^ Edibility:
                if arg.kind == T.EDIBLE:
                    return true
                else:
                    return false
            else:
                raise SemantičkaGreška('Nepodržana konverzija iz tipa ' + str(type(arg)) + ' u tip ' + str(self.type))
            
        elif self.type ^ T.NUMBER:
            if len(self.arguments) != 1:
                raise SemantičkaGreška('Konstruktor broja prima jedan argument')
            arg = self.arguments[0].vrijednost()
            if type(arg) == bool: # konverzija Bool->Number: 1 ako True, inače 0
                if arg:
                    return Number(1, None)
                else:
                    return Number(0, None)
            elif arg ^ Number:
                return arg
            elif type(arg) == str: # konverzija String->Number: koristimo Pythonovu semantiku
                tmp = float(arg)
                return Number(tmp, None)
            else:
                raise SemantičkaGreška('Nepodržana konverzija iz tipa ' + str(type(arg)) + ' u tip ' + str(self.type))
            
        elif self.type ^ T.STRINGTYPE:
            if len(self.arguments) != 1:
                raise SemantičkaGreška('Konstruktor stringa prima jedan argument')
            arg = self.arguments[0].vrijednost()
            if type(arg) == bool: # konverzija Bool->String: daje 'True' za istinu, a inače prazan string, kako bi bilo konzistentno s obrnutom konverzijom
                if arg:
                    return 'True'
                else:
                    return ''
            elif arg ^ Number: # konverzija Number->String: kao Python
                tmp = str(arg.value)
                if arg.unit:
                    tmp += ' ' + arg.unit.sadržaj
                return tmp
            elif type(arg) == str:
                return arg
            else:
                return arg.to_string()
            
        elif self.type ^ T.DATETIME:
            if len(self.arguments) >= 3:
                day = self.arguments[0].vrijednost()
                month = self.arguments[0].vrijednost()
                year = self.arguments[0].vrijednost()
                for el in [day, month, year]:
                    try:
                        if type(el) == str:
                            el = int(el)
                        elif el ^ Number:
                            el = int(el.value)
                        else:
                            raise SemantičkaGreška('Nepodržan tip za dan/mjesec/godinu')
                    except: raise SemantičkaGreška('Nemoguće konstruirati datum iz danih argumenata')
                if len(self.arguments) > 3:
                    minutes = 0
                    seconds = 0
                    for el in [comp.vrijednost() for comp in self.arguments[3:]]:
                        try:
                            if type(el) == str:
                                el = int(el)
                            elif el ^ Number:
                                el = int(el.value)
                            else:
                                raise SemantičkaGreška('Nepodržan tip za vrijeme')
                        except: raise SemantičkaGreška('Nemoguće konstruirati vrijeme iz danih argumenata')
                    hours = el[0]
                    if len(el) > 1:
                        minutes = el[1]
                    if len(el) > 2:
                        seconds = el[2]
                    if len(el) > 3:
                        raise SemantičkaGreška('Konstrukcija vremena uzima najviše tri argumenta: sati, minute i sekunde')
                    tmp = DateTime([day, month, year], hours, minutes, seconds)
                    tmp.validiraj()
                    return tmp
                else:
                    tmp = Date([day, month, year])
                    tmp.validiraj()
                    return tmp
            else:
                arg = self.arguments[0].vrijednost()
                if not arg ^ Date or not arg ^ DateTime:
                    raise SemantičkaGreška('Datum/vrijeme se može konstruirati samo iz literala datuma/vremena')
                return arg                    
            
        elif self.type ^ T.FUNGUS: 
            # nema konvertirajućeg konstruktora
            args = [arg.vrijednost() for arg in self.arguments]
            date = None
            if type(args[0]) != str:
                raise SemantičkaGreška('Prvi argument konstruktora za Fungus mora biti ime')
            if type(args[1]) != str:
                raise SemantičkaGreška('Drugi argument konstruktora za Fungus mora biti latinsko ime')
            if not args[2] ^ DNA:
                raise SemantičkaGreška('Treći argument konstruktora za Fungus mora biti DNA')
            if not args[3] ^ Tree:
                raise SemantičkaGreška('Četvrti argument konstruktora za Fungus mora biti taksonomija')
            if len(args) == 5: # prihvaćamo i eksplicitan vrijeme unošenja uzorka
                if not  args[4] ^ Date and not args[4] ^ DateTime:
                    raise SemantičkaGreška('Peti (opcionalni) argument konstruktora za Fungus mora biti datum/vrijeme')
                date = args[4]
            else: # ako nema vremena, uzima se trenutno
                now = datetime.datetime.now()
                date = DateTime([now.day, now.month, now.year], now.hour, now.minute, now.second)
            return Fungus(args[0], args[1], args[2], args[3], date)
        
        elif self.type ^ T.TREE:
            return Tree() # taksonomija se samo "defaultno" konstruira tj. dobivamo ne baš korisan objekt u kojem se onda moraju postavljati komponente
        # koristeći . operator
        elif self.type ^ T.EDIBILITY:
            return Edibility(self.arguments[0])
        else:
            raise SemantičkaGreška('Nemoguća situacija?!')


    def get_list_length(self):
        return None
    
class Fungus(AST): # NAPOMENA: ovo ustvari *nije* AST tj. nešto što parser konstruira već služi samo interpreteru; koristimo AST baznu klasu jer pruža neke
    # zgodne defaulte
    # imamo bar 4 argumenta: # mora se navesti ime,latinsko ime,dna,taksonomija; opcionalno je još i Datetime pronalaska/unosa uzorka
    name: ...
    latin: ...
    dna: ...
    taxonomy: ...
    timestamp: ...

    def __eq__(self, other): # za usporedbu gljiva uzimamo latinski naziv kao primarni ključ
        return self.latin == other.latin
    
    def __ne__(self, other):
        return self.latin != other.latin

    def to_string(self):
        tmp = 'Name: ' + self.name + '\n'
        +     'Latin name: ' + self.latin + '\n'
        +     'DNA: ' + self.dna.to_string() + '\n'
        +     'Taxonomy: ' + self.taxonomy.to_string() + '\n'
        +     'Time found: ' + self.timestamp.to_string()
        return tmp

#SPECIES, GENUS, FAMILY, ORDER, CLASS, PHYLUM, KINGDOM = 'spec', 'gen', 'fam', 'ord', 'class', 'phyl', 'king'
class Tree:
    species: ...
    genus: ...
    family: ...
    order: ...
    klasa: ...
    phylum: ...
    kingdom: ...

    def __eq__(self, other):
        for prop in ['species', 'genus', 'family', 'order', 'klasa', 'phylum', 'kingdom']:
            if hasattr(self, prop) ^ hasattr(other, prop):
                return False
            elif hasattr(self, prop) and hasattr(other, prop):
                val1 = getattr(self, prop, None)
                val2 = getattr(other, prop, None)
                if val1 != val2:
                    return False
        return True
    
    def __ne__(self, other):
        return not self.__eq__(other)

    def to_string(self):
        tmp = ''
        for prop in ['species', 'genus', 'family', 'order', 'klasa', 'phylum', 'kingdom']:
            val = getattr(self, prop, None)
            if val:
                tmp += prop + ': ' + val + '\n'
        return tmp

class Date(AST):
    date: ... #(day,month,year) triple

    def __eq__(self, other):
        for i in range(3):
            if self.date[i] != other.date[i]:
                return False
            
        return True
    
    def __ne__(self, other):
        return not self.__eq__(other)

    def vrijednost(self):
        return self
    
    def validiraj(self):
            dijelovi = self.date
            if dijelovi[0] < 0 or dijelovi[0] > 31 or dijelovi[1] > 12 or dijelovi[1] < 1 or dijelovi[2] < 1000 or dijelovi[2] > 9999:
                raise SemantičkaGreška('Nemoguć datum')
            
            return True

    def get_list_length(self):
        return None
    
    def to_string(self):
        return self.date[0] + '.' + self.date[1] + '.' + self.date[2] + '.'

class DateTime(Date):
    hours: ...
    minutes: ...
    seconds: ...

    def __eq__(self, other):
        res = super().__eq__(other)
        if not res:
            return False
        if self.hours == other.hours and self.minutes == other.minutes and self.seconds == other.seconds:
            return True
        return False
    
    def __ne__(self, other):
        return not self.__eq__(other)

    def validiraj(self):
        super().validiraj()
        if self.hours < 0 or self.hours >= 24:
            raise SemantičkaGreška('Sati moraju biti iz [0,24>')
        if self.minutes < 0 or self.minutes >= 60:
            raise SemantičkaGreška('Minute moraju biti iz [0, 60>')
        if self.seconds < 0 or self.seconds >= 60:
            raise SemantičkaGreška('Sekunde moraju biti iz [0, 60>')
        return True

    def get_list_length(self):
        return None
    
    def to_string(self):
        tmp = super().to_string()
        tmp += ' ' + self.hours + ':' + self.minutes + ':' + self.seconds
        return tmp
    
class DNA(AST):
    bases: ...

    def __eq__(self, other):
        for b1,b2 in zip(self.bases, other.bases):
            if b1 != b2:
                return False
            
        return True
    
    def __ne__(self, other):
        return not self.__eq__(other)

    def vrijednost(self):
        return self
    
    def to_string(self):
        tmp = ''
        for b in self.bases:
            tmp += b
        return tmp

class List(DotList):
    # def __eq__(self, other):
    #     if len(self.elements) != len(other.elements):
    #         return False
    #     for el1,el2 in zip(self.elements, other.elements):


    def vrijednost(self):
        return self.elements
    
    def get_list_length(self):
        return len(self.elements)
    
    def to_string(self):
        tmp = '['
        for el in self.elements:
            tmp += el.to_string() + ', '
        tmp += ']'
        return tmp

class Edibility(AST):
    kind: ...

    def __eq__(self, other):
        return self.kind.sadržaj == other.kind.sadržaj
    
    def __ne__(self, other):
        return self.kind.sadržaj != other.kind.sadržaj

    def vrijednost(self):
        return self

    def get_list_length(self):
        return None
    
    def to_string(self):
        return self.kind.sadržaj

class Declaration(AST):
    variable: ...

    def izvrši(self):
        rt.okolina[-1][self.variable] = None

