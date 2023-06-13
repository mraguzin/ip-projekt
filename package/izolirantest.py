from vepar import *

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
    FOR, IF = 'for', 'if'
    TRUE, FALSE = 'true', 'false'
    SETPARAM = 'setParam'  #ovo je builtin funkcija koja služi interaktivnoj izmjeni/prilagodbi globalnihparametara evolucijskih operatora
    # kako bi se dobili željeni
    # populacijski rezultati kroz simulirane generacije gljiva. Sami parametri nisu hardkodirani u jeziku; predaju se kao param:val parovi
    #  i interpreter je dužan nositi se s njima kako spada. Npr. setParam("param1:")

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
            if not is_stringetic(args[0]) or is_list(args[0]) or not is_stringetic(args[1]) or is_list(args[1]) or not args[2] ^ {T.IME, DNA} or not(args[3] ^ T.IME or args[3] ^ ConstructorCall and not args[3].type ^ T.TREE):
                raise SemantičkaGreška('Konstruktor Fungus-a traži ime,latinsko ime,DNA,taksonomiju i opcionalno još vrijeme pronalaska')
            if len(args) == 5 and (not is_datetime(args[4]) or is_list(args[4])):
                raise SemantičkaGreška('Opcionalni argument Fungus konstruktora je datum/vrijeme')
            return True
    class TREE(Token):
        literal = 'Tree'
        def validate_call(self, *args):
            if len(args) != 0:
                raise SemantičkaGreška('Konstruktor Tree-a je bez parametara')
            return True
    class EDIBILITY(Token):
        literal = 'Edibility'
        def validate_call(self, *args):
            if len(args) != 1:
                raise SemantičkaGreška('Konstruktor Edibility-ja traži jednu od kontekstualnih ključnih riječi za jestivost/toksičnost')
            kind = args[0]
            if not kind ^ {T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE}:
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
        
        def validiraj(self):
            dijelovi = self.vrijednost()
            if dijelovi[0] < 0 or dijelovi[0] > 31 or dijelovi[1] > 12 or dijelovi[1] < 1 or dijelovi[2] < 1000 or dijelovi[2] > 9999:
                raise SemantičkaGreška('Nemoguć datum')
            
            return True
            
    class READ(Token):
        literal = 'read'
        def validate_call(self, *args):
            if len(args) != 1:
                raise SintaksnaGreška('read funkcija očekuje jedan argument: ime tekstualne datoteke za pročitati')
        def get_list_length(self):
            return None
    class WRITE(Token):
        literal = 'write'
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
                    raise lex.greška('Ilegalan format datuma') #TODO: detaljni error reporting za datume u fazi parsiranja
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

miko('9')