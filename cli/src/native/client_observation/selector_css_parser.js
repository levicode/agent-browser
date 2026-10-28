// Copyright (c) Microsoft Corporation. Licensed under Apache-2.0.
// Guarded parser only, derived from pinned Playwright1.64.1; no DOM execution.
function createRawCssParser(__step, __limit) {
let __depth=0;
function __enter(){__step();if(__depth>=256)throw __limit;++__depth;}
function __leave(){--__depth;}
// packages/isomorphic/cssTokenizer.ts
var between = function (num, first, last) {
    __enter();
    try {
        return num >= first && num <= last;
    }
    finally {
        __leave();
    }
};
function digit(code) {
    __enter();
    try {
        return between(code, 48, 57);
    }
    finally {
        __leave();
    }
}
function hexdigit(code) {
    __enter();
    try {
        return digit(code) || between(code, 65, 70) || between(code, 97, 102);
    }
    finally {
        __leave();
    }
}
function uppercaseletter(code) {
    __enter();
    try {
        return between(code, 65, 90);
    }
    finally {
        __leave();
    }
}
function lowercaseletter(code) {
    __enter();
    try {
        return between(code, 97, 122);
    }
    finally {
        __leave();
    }
}
function letter(code) {
    __enter();
    try {
        return uppercaseletter(code) || lowercaseletter(code);
    }
    finally {
        __leave();
    }
}
function nonascii(code) {
    __enter();
    try {
        return code >= 128;
    }
    finally {
        __leave();
    }
}
function namestartchar(code) {
    __enter();
    try {
        return letter(code) || nonascii(code) || code === 95;
    }
    finally {
        __leave();
    }
}
function namechar(code) {
    __enter();
    try {
        return namestartchar(code) || digit(code) || code === 45;
    }
    finally {
        __leave();
    }
}
function nonprintable(code) {
    __enter();
    try {
        return between(code, 0, 8) || code === 11 || between(code, 14, 31) || code === 127;
    }
    finally {
        __leave();
    }
}
function newline(code) {
    __enter();
    try {
        return code === 10;
    }
    finally {
        __leave();
    }
}
function whitespace(code) {
    __enter();
    try {
        return newline(code) || code === 9 || code === 32;
    }
    finally {
        __leave();
    }
}
var maximumallowedcodepoint = 1114111;
var InvalidCharacterError = class extends Error {
    constructor(message) {
        __enter();
        try {
            super(message);
            this.name = "InvalidCharacterError";
        }
        finally {
            __leave();
        }
    }
};
function preprocess(str) {
    __enter();
    try {
        const codepoints = [];
        for (let i = 0; i < str.length; i++) {
            __step();
            let code = str.charCodeAt(i);
            if (code === 13 && str.charCodeAt(i + 1) === 10) {
                code = 10;
                i++;
            }
            if (code === 13 || code === 12)
                code = 10;
            if (code === 0)
                code = 65533;
            if (between(code, 55296, 56319) && between(str.charCodeAt(i + 1), 56320, 57343)) {
                const lead = code - 55296;
                const trail = str.charCodeAt(i + 1) - 56320;
                code = Math.pow(2, 16) + lead * Math.pow(2, 10) + trail;
                i++;
            }
            codepoints.push(code);
        }
        return codepoints;
    }
    finally {
        __leave();
    }
}
function stringFromCode(code) {
    __enter();
    try {
        if (code <= 65535)
            return String.fromCharCode(code);
        code -= Math.pow(2, 16);
        const lead = Math.floor(code / Math.pow(2, 10)) + 55296;
        const trail = code % Math.pow(2, 10) + 56320;
        return String.fromCharCode(lead) + String.fromCharCode(trail);
    }
    finally {
        __leave();
    }
}
function tokenize(str1) {
    __enter();
    try {
        const str = preprocess(str1);
        let i = -1;
        const tokens = [];
        let code;
        let line = 0;
        let column = 0;
        let lastLineLength = 0;
        const incrLineno = function () {
            __enter();
            try {
                line += 1;
                lastLineLength = column;
                column = 0;
            }
            finally {
                __leave();
            }
        };
        const locStart = { line, column };
        const codepoint = function (i2) {
            __enter();
            try {
                if (i2 >= str.length)
                    return -1;
                return str[i2];
            }
            finally {
                __leave();
            }
        };
        const next = function (num) {
            __enter();
            try {
                if (num === void 0)
                    num = 1;
                if (num > 3)
                    throw "Spec Error: no more than three codepoints of lookahead.";
                return codepoint(i + num);
            }
            finally {
                __leave();
            }
        };
        const consume = function (num) {
            __enter();
            try {
                if (num === void 0)
                    num = 1;
                i += num;
                code = codepoint(i);
                if (newline(code))
                    incrLineno();
                else
                    column += num;
                return true;
            }
            finally {
                __leave();
            }
        };
        const reconsume = function () {
            __enter();
            try {
                i -= 1;
                if (newline(code)) {
                    line -= 1;
                    column = lastLineLength;
                }
                else {
                    column -= 1;
                }
                locStart.line = line;
                locStart.column = column;
                return true;
            }
            finally {
                __leave();
            }
        };
        const eof = function (codepoint2) {
            __enter();
            try {
                if (codepoint2 === void 0)
                    codepoint2 = code;
                return codepoint2 === -1;
            }
            finally {
                __leave();
            }
        };
        const donothing = function () {
            __enter();
            try {
            }
            finally {
                __leave();
            }
        };
        const parseerror = function () {
            __enter();
            try {
            }
            finally {
                __leave();
            }
        };
        const consumeAToken = function () {
            __enter();
            try {
                consumeComments();
                consume();
                if (whitespace(code)) {
                    while (whitespace(next())) {
                        __step();
                        consume();
                    }
                    return new WhitespaceToken();
                }
                else if (code === 34) {
                    return consumeAStringToken();
                }
                else if (code === 35) {
                    if (namechar(next()) || areAValidEscape(next(1), next(2))) {
                        const token = new HashToken("");
                        if (wouldStartAnIdentifier(next(1), next(2), next(3)))
                            token.type = "id";
                        token.value = consumeAName();
                        return token;
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (code === 36) {
                    if (next() === 61) {
                        consume();
                        return new SuffixMatchToken();
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (code === 39) {
                    return consumeAStringToken();
                }
                else if (code === 40) {
                    return new OpenParenToken();
                }
                else if (code === 41) {
                    return new CloseParenToken();
                }
                else if (code === 42) {
                    if (next() === 61) {
                        consume();
                        return new SubstringMatchToken();
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (code === 43) {
                    if (startsWithANumber()) {
                        reconsume();
                        return consumeANumericToken();
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (code === 44) {
                    return new CommaToken();
                }
                else if (code === 45) {
                    if (startsWithANumber()) {
                        reconsume();
                        return consumeANumericToken();
                    }
                    else if (next(1) === 45 && next(2) === 62) {
                        consume(2);
                        return new CDCToken();
                    }
                    else if (startsWithAnIdentifier()) {
                        reconsume();
                        return consumeAnIdentlikeToken();
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (code === 46) {
                    if (startsWithANumber()) {
                        reconsume();
                        return consumeANumericToken();
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (code === 58) {
                    return new ColonToken();
                }
                else if (code === 59) {
                    return new SemicolonToken();
                }
                else if (code === 60) {
                    if (next(1) === 33 && next(2) === 45 && next(3) === 45) {
                        consume(3);
                        return new CDOToken();
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (code === 64) {
                    if (wouldStartAnIdentifier(next(1), next(2), next(3)))
                        return new AtKeywordToken(consumeAName());
                    else
                        return new DelimToken(code);
                }
                else if (code === 91) {
                    return new OpenSquareToken();
                }
                else if (code === 92) {
                    if (startsWithAValidEscape()) {
                        reconsume();
                        return consumeAnIdentlikeToken();
                    }
                    else {
                        parseerror();
                        return new DelimToken(code);
                    }
                }
                else if (code === 93) {
                    return new CloseSquareToken();
                }
                else if (code === 94) {
                    if (next() === 61) {
                        consume();
                        return new PrefixMatchToken();
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (code === 123) {
                    return new OpenCurlyToken();
                }
                else if (code === 124) {
                    if (next() === 61) {
                        consume();
                        return new DashMatchToken();
                    }
                    else if (next() === 124) {
                        consume();
                        return new ColumnToken();
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (code === 125) {
                    return new CloseCurlyToken();
                }
                else if (code === 126) {
                    if (next() === 61) {
                        consume();
                        return new IncludeMatchToken();
                    }
                    else {
                        return new DelimToken(code);
                    }
                }
                else if (digit(code)) {
                    reconsume();
                    return consumeANumericToken();
                }
                else if (namestartchar(code)) {
                    reconsume();
                    return consumeAnIdentlikeToken();
                }
                else if (eof()) {
                    return new EOFToken();
                }
                else {
                    return new DelimToken(code);
                }
            }
            finally {
                __leave();
            }
        };
        const consumeComments = function () {
            __enter();
            try {
                while (next(1) === 47 && next(2) === 42) {
                    __step();
                    consume(2);
                    while (true) {
                        __step();
                        consume();
                        if (code === 42 && next() === 47) {
                            consume();
                            break;
                        }
                        else if (eof()) {
                            parseerror();
                            return;
                        }
                    }
                }
            }
            finally {
                __leave();
            }
        };
        const consumeANumericToken = function () {
            __enter();
            try {
                const num = consumeANumber();
                if (wouldStartAnIdentifier(next(1), next(2), next(3))) {
                    const token = new DimensionToken();
                    token.value = num.value;
                    token.repr = num.repr;
                    token.type = num.type;
                    token.unit = consumeAName();
                    return token;
                }
                else if (next() === 37) {
                    consume();
                    const token = new PercentageToken();
                    token.value = num.value;
                    token.repr = num.repr;
                    return token;
                }
                else {
                    const token = new NumberToken();
                    token.value = num.value;
                    token.repr = num.repr;
                    token.type = num.type;
                    return token;
                }
            }
            finally {
                __leave();
            }
        };
        const consumeAnIdentlikeToken = function () {
            __enter();
            try {
                const str2 = consumeAName();
                if (str2.toLowerCase() === "url" && next() === 40) {
                    consume();
                    while (whitespace(next(1)) && whitespace(next(2))) {
                        __step();
                        consume();
                    }
                    if (next() === 34 || next() === 39)
                        return new FunctionToken(str2);
                    else if (whitespace(next()) && (next(2) === 34 || next(2) === 39))
                        return new FunctionToken(str2);
                    else
                        return consumeAURLToken();
                }
                else if (next() === 40) {
                    consume();
                    return new FunctionToken(str2);
                }
                else {
                    return new IdentToken(str2);
                }
            }
            finally {
                __leave();
            }
        };
        const consumeAStringToken = function (endingCodePoint) {
            __enter();
            try {
                if (endingCodePoint === void 0)
                    endingCodePoint = code;
                let string = "";
                while (consume()) {
                    __step();
                    if (code === endingCodePoint || eof()) {
                        return new StringToken(string);
                    }
                    else if (newline(code)) {
                        parseerror();
                        reconsume();
                        return new BadStringToken();
                    }
                    else if (code === 92) {
                        if (eof(next()))
                            donothing();
                        else if (newline(next()))
                            consume();
                        else
                            string += stringFromCode(consumeEscape());
                    }
                    else {
                        string += stringFromCode(code);
                    }
                }
                throw new Error("Internal error");
            }
            finally {
                __leave();
            }
        };
        const consumeAURLToken = function () {
            __enter();
            try {
                const token = new URLToken("");
                while (whitespace(next())) {
                    __step();
                    consume();
                }
                if (eof(next()))
                    return token;
                while (consume()) {
                    __step();
                    if (code === 41 || eof()) {
                        return token;
                    }
                    else if (whitespace(code)) {
                        while (whitespace(next())) {
                            __step();
                            consume();
                        }
                        if (next() === 41 || eof(next())) {
                            consume();
                            return token;
                        }
                        else {
                            consumeTheRemnantsOfABadURL();
                            return new BadURLToken();
                        }
                    }
                    else if (code === 34 || code === 39 || code === 40 || nonprintable(code)) {
                        parseerror();
                        consumeTheRemnantsOfABadURL();
                        return new BadURLToken();
                    }
                    else if (code === 92) {
                        if (startsWithAValidEscape()) {
                            token.value += stringFromCode(consumeEscape());
                        }
                        else {
                            parseerror();
                            consumeTheRemnantsOfABadURL();
                            return new BadURLToken();
                        }
                    }
                    else {
                        token.value += stringFromCode(code);
                    }
                }
                throw new Error("Internal error");
            }
            finally {
                __leave();
            }
        };
        const consumeEscape = function () {
            __enter();
            try {
                consume();
                if (hexdigit(code)) {
                    const digits = [code];
                    for (let total = 0; total < 5; total++) {
                        __step();
                        if (hexdigit(next())) {
                            consume();
                            digits.push(code);
                        }
                        else {
                            break;
                        }
                    }
                    if (whitespace(next()))
                        consume();
                    let value = parseInt(digits.map(function (x) {
                        __enter();
                        try {
                            return String.fromCharCode(x);
                        }
                        finally {
                            __leave();
                        }
                    }).join(""), 16);
                    if (value > maximumallowedcodepoint)
                        value = 65533;
                    return value;
                }
                else if (eof()) {
                    return 65533;
                }
                else {
                    return code;
                }
            }
            finally {
                __leave();
            }
        };
        const areAValidEscape = function (c1, c2) {
            __enter();
            try {
                if (c1 !== 92)
                    return false;
                if (newline(c2))
                    return false;
                return true;
            }
            finally {
                __leave();
            }
        };
        const startsWithAValidEscape = function () {
            __enter();
            try {
                return areAValidEscape(code, next());
            }
            finally {
                __leave();
            }
        };
        const wouldStartAnIdentifier = function (c1, c2, c3) {
            __enter();
            try {
                if (c1 === 45)
                    return namestartchar(c2) || c2 === 45 || areAValidEscape(c2, c3);
                else if (namestartchar(c1))
                    return true;
                else if (c1 === 92)
                    return areAValidEscape(c1, c2);
                else
                    return false;
            }
            finally {
                __leave();
            }
        };
        const startsWithAnIdentifier = function () {
            __enter();
            try {
                return wouldStartAnIdentifier(code, next(1), next(2));
            }
            finally {
                __leave();
            }
        };
        const wouldStartANumber = function (c1, c2, c3) {
            __enter();
            try {
                if (c1 === 43 || c1 === 45) {
                    if (digit(c2))
                        return true;
                    if (c2 === 46 && digit(c3))
                        return true;
                    return false;
                }
                else if (c1 === 46) {
                    if (digit(c2))
                        return true;
                    return false;
                }
                else if (digit(c1)) {
                    return true;
                }
                else {
                    return false;
                }
            }
            finally {
                __leave();
            }
        };
        const startsWithANumber = function () {
            __enter();
            try {
                return wouldStartANumber(code, next(1), next(2));
            }
            finally {
                __leave();
            }
        };
        const consumeAName = function () {
            __enter();
            try {
                let result = "";
                while (consume()) {
                    __step();
                    if (namechar(code)) {
                        result += stringFromCode(code);
                    }
                    else if (startsWithAValidEscape()) {
                        result += stringFromCode(consumeEscape());
                    }
                    else {
                        reconsume();
                        return result;
                    }
                }
                throw new Error("Internal parse error");
            }
            finally {
                __leave();
            }
        };
        const consumeANumber = function () {
            __enter();
            try {
                let repr = "";
                let type = "integer";
                if (next() === 43 || next() === 45) {
                    consume();
                    repr += stringFromCode(code);
                }
                while (digit(next())) {
                    __step();
                    consume();
                    repr += stringFromCode(code);
                }
                if (next(1) === 46 && digit(next(2))) {
                    consume();
                    repr += stringFromCode(code);
                    consume();
                    repr += stringFromCode(code);
                    type = "number";
                    while (digit(next())) {
                        __step();
                        consume();
                        repr += stringFromCode(code);
                    }
                }
                const c1 = next(1);
                const c2 = next(2);
                const c3 = next(3);
                if ((c1 === 69 || c1 === 101) && digit(c2)) {
                    consume();
                    repr += stringFromCode(code);
                    consume();
                    repr += stringFromCode(code);
                    type = "number";
                    while (digit(next())) {
                        __step();
                        consume();
                        repr += stringFromCode(code);
                    }
                }
                else if ((c1 === 69 || c1 === 101) && (c2 === 43 || c2 === 45) && digit(c3)) {
                    consume();
                    repr += stringFromCode(code);
                    consume();
                    repr += stringFromCode(code);
                    consume();
                    repr += stringFromCode(code);
                    type = "number";
                    while (digit(next())) {
                        __step();
                        consume();
                        repr += stringFromCode(code);
                    }
                }
                const value = convertAStringToANumber(repr);
                return { type, value, repr };
            }
            finally {
                __leave();
            }
        };
        const convertAStringToANumber = function (string) {
            __enter();
            try {
                return +string;
            }
            finally {
                __leave();
            }
        };
        const consumeTheRemnantsOfABadURL = function () {
            __enter();
            try {
                while (consume()) {
                    __step();
                    if (code === 41 || eof()) {
                        return;
                    }
                    else if (startsWithAValidEscape()) {
                        consumeEscape();
                        donothing();
                    }
                    else {
                        donothing();
                    }
                }
            }
            finally {
                __leave();
            }
        };
        let iterationCount = 0;
        while (!eof(next())) {
            __step();
            tokens.push(consumeAToken());
            iterationCount++;
            if (iterationCount > str.length * 2)
                throw new Error("I'm infinite-looping!");
        }
        return tokens;
    }
    finally {
        __leave();
    }
}
var CSSParserToken = class {
    constructor() {
        __enter();
        try {
            this.tokenType = "";
        }
        finally {
            __leave();
        }
    }
    toJSON() {
        __enter();
        try {
            return { token: this.tokenType };
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return this.tokenType;
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return "" + this;
        }
        finally {
            __leave();
        }
    }
};
var BadStringToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "BADSTRING";
        }
        finally {
            __leave();
        }
    }
};
var BadURLToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "BADURL";
        }
        finally {
            __leave();
        }
    }
};
var WhitespaceToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "WHITESPACE";
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return "WS";
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return " ";
        }
        finally {
            __leave();
        }
    }
};
var CDOToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "CDO";
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return "<!--";
        }
        finally {
            __leave();
        }
    }
};
var CDCToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "CDC";
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return "-->";
        }
        finally {
            __leave();
        }
    }
};
var ColonToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = ":";
        }
        finally {
            __leave();
        }
    }
};
var SemicolonToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = ";";
        }
        finally {
            __leave();
        }
    }
};
var CommaToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = ",";
        }
        finally {
            __leave();
        }
    }
};
var GroupingToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.value = "";
            this.mirror = "";
        }
        finally {
            __leave();
        }
    }
};
var OpenCurlyToken = class extends GroupingToken {
    constructor() {
        __enter();
        try {
            super();
            this.tokenType = "{";
            this.value = "{";
            this.mirror = "}";
        }
        finally {
            __leave();
        }
    }
};
var CloseCurlyToken = class extends GroupingToken {
    constructor() {
        __enter();
        try {
            super();
            this.tokenType = "}";
            this.value = "}";
            this.mirror = "{";
        }
        finally {
            __leave();
        }
    }
};
var OpenSquareToken = class extends GroupingToken {
    constructor() {
        __enter();
        try {
            super();
            this.tokenType = "[";
            this.value = "[";
            this.mirror = "]";
        }
        finally {
            __leave();
        }
    }
};
var CloseSquareToken = class extends GroupingToken {
    constructor() {
        __enter();
        try {
            super();
            this.tokenType = "]";
            this.value = "]";
            this.mirror = "[";
        }
        finally {
            __leave();
        }
    }
};
var OpenParenToken = class extends GroupingToken {
    constructor() {
        __enter();
        try {
            super();
            this.tokenType = "(";
            this.value = "(";
            this.mirror = ")";
        }
        finally {
            __leave();
        }
    }
};
var CloseParenToken = class extends GroupingToken {
    constructor() {
        __enter();
        try {
            super();
            this.tokenType = ")";
            this.value = ")";
            this.mirror = "(";
        }
        finally {
            __leave();
        }
    }
};
var IncludeMatchToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "~=";
        }
        finally {
            __leave();
        }
    }
};
var DashMatchToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "|=";
        }
        finally {
            __leave();
        }
    }
};
var PrefixMatchToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "^=";
        }
        finally {
            __leave();
        }
    }
};
var SuffixMatchToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "$=";
        }
        finally {
            __leave();
        }
    }
};
var SubstringMatchToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "*=";
        }
        finally {
            __leave();
        }
    }
};
var ColumnToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "||";
        }
        finally {
            __leave();
        }
    }
};
var EOFToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.tokenType = "EOF";
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return "";
        }
        finally {
            __leave();
        }
    }
};
var DelimToken = class extends CSSParserToken {
    constructor(code) {
        __enter();
        try {
            super();
            this.tokenType = "DELIM";
            this.value = "";
            this.value = stringFromCode(code);
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return "DELIM(" + this.value + ")";
        }
        finally {
            __leave();
        }
    }
    toJSON() {
        __enter();
        try {
            const json = this.constructor.prototype.constructor.prototype.toJSON.call(this);
            json.value = this.value;
            return json;
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            if (this.value === "\\")
                return "\\\n";
            else
                return this.value;
        }
        finally {
            __leave();
        }
    }
};
var StringValuedToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super(...arguments);
            this.value = "";
        }
        finally {
            __leave();
        }
    }
    ASCIIMatch(str) {
        __enter();
        try {
            return this.value.toLowerCase() === str.toLowerCase();
        }
        finally {
            __leave();
        }
    }
    toJSON() {
        __enter();
        try {
            const json = this.constructor.prototype.constructor.prototype.toJSON.call(this);
            json.value = this.value;
            return json;
        }
        finally {
            __leave();
        }
    }
};
var IdentToken = class extends StringValuedToken {
    constructor(val) {
        __enter();
        try {
            super();
            this.tokenType = "IDENT";
            this.value = val;
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return "IDENT(" + this.value + ")";
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return escapeIdent(this.value);
        }
        finally {
            __leave();
        }
    }
};
var FunctionToken = class extends StringValuedToken {
    constructor(val) {
        __enter();
        try {
            super();
            this.tokenType = "FUNCTION";
            this.value = val;
            this.mirror = ")";
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return "FUNCTION(" + this.value + ")";
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return escapeIdent(this.value) + "(";
        }
        finally {
            __leave();
        }
    }
};
var AtKeywordToken = class extends StringValuedToken {
    constructor(val) {
        __enter();
        try {
            super();
            this.tokenType = "AT-KEYWORD";
            this.value = val;
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return "AT(" + this.value + ")";
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return "@" + escapeIdent(this.value);
        }
        finally {
            __leave();
        }
    }
};
var HashToken = class extends StringValuedToken {
    constructor(val) {
        __enter();
        try {
            super();
            this.tokenType = "HASH";
            this.value = val;
            this.type = "unrestricted";
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return "HASH(" + this.value + ")";
        }
        finally {
            __leave();
        }
    }
    toJSON() {
        __enter();
        try {
            const json = this.constructor.prototype.constructor.prototype.toJSON.call(this);
            json.value = this.value;
            json.type = this.type;
            return json;
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            if (this.type === "id")
                return "#" + escapeIdent(this.value);
            else
                return "#" + escapeHash(this.value);
        }
        finally {
            __leave();
        }
    }
};
var StringToken = class extends StringValuedToken {
    constructor(val) {
        __enter();
        try {
            super();
            this.tokenType = "STRING";
            this.value = val;
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return '"' + escapeString(this.value) + '"';
        }
        finally {
            __leave();
        }
    }
};
var URLToken = class extends StringValuedToken {
    constructor(val) {
        __enter();
        try {
            super();
            this.tokenType = "URL";
            this.value = val;
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return "URL(" + this.value + ")";
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return 'url("' + escapeString(this.value) + '")';
        }
        finally {
            __leave();
        }
    }
};
var NumberToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super();
            this.tokenType = "NUMBER";
            this.type = "integer";
            this.repr = "";
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            if (this.type === "integer")
                return "INT(" + this.value + ")";
            return "NUMBER(" + this.value + ")";
        }
        finally {
            __leave();
        }
    }
    toJSON() {
        __enter();
        try {
            const json = super.toJSON();
            json.value = this.value;
            json.type = this.type;
            json.repr = this.repr;
            return json;
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return this.repr;
        }
        finally {
            __leave();
        }
    }
};
var PercentageToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super();
            this.tokenType = "PERCENTAGE";
            this.repr = "";
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return "PERCENTAGE(" + this.value + ")";
        }
        finally {
            __leave();
        }
    }
    toJSON() {
        __enter();
        try {
            const json = this.constructor.prototype.constructor.prototype.toJSON.call(this);
            json.value = this.value;
            json.repr = this.repr;
            return json;
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            return this.repr + "%";
        }
        finally {
            __leave();
        }
    }
};
var DimensionToken = class extends CSSParserToken {
    constructor() {
        __enter();
        try {
            super();
            this.tokenType = "DIMENSION";
            this.type = "integer";
            this.repr = "";
            this.unit = "";
        }
        finally {
            __leave();
        }
    }
    toString() {
        __enter();
        try {
            return "DIM(" + this.value + "," + this.unit + ")";
        }
        finally {
            __leave();
        }
    }
    toJSON() {
        __enter();
        try {
            const json = this.constructor.prototype.constructor.prototype.toJSON.call(this);
            json.value = this.value;
            json.type = this.type;
            json.repr = this.repr;
            json.unit = this.unit;
            return json;
        }
        finally {
            __leave();
        }
    }
    toSource() {
        __enter();
        try {
            const source = this.repr;
            let unit = escapeIdent(this.unit);
            if (unit[0].toLowerCase() === "e" && (unit[1] === "-" || between(unit.charCodeAt(1), 48, 57))) {
                unit = "\\65 " + unit.slice(1, unit.length);
            }
            return source + unit;
        }
        finally {
            __leave();
        }
    }
};
function escapeIdent(string) {
    __enter();
    try {
        string = "" + string;
        let result = "";
        const firstcode = string.charCodeAt(0);
        for (let i = 0; i < string.length; i++) {
            __step();
            const code = string.charCodeAt(i);
            if (code === 0)
                throw new InvalidCharacterError("Invalid character: the input contains U+0000.");
            if (between(code, 1, 31) || code === 127 || i === 0 && between(code, 48, 57) || i === 1 && between(code, 48, 57) && firstcode === 45)
                result += "\\" + code.toString(16) + " ";
            else if (code >= 128 || code === 45 || code === 95 || between(code, 48, 57) || between(code, 65, 90) || between(code, 97, 122))
                result += string[i];
            else
                result += "\\" + string[i];
        }
        return result;
    }
    finally {
        __leave();
    }
}
function escapeHash(string) {
    __enter();
    try {
        string = "" + string;
        let result = "";
        for (let i = 0; i < string.length; i++) {
            __step();
            const code = string.charCodeAt(i);
            if (code === 0)
                throw new InvalidCharacterError("Invalid character: the input contains U+0000.");
            if (code >= 128 || code === 45 || code === 95 || between(code, 48, 57) || between(code, 65, 90) || between(code, 97, 122))
                result += string[i];
            else
                result += "\\" + code.toString(16) + " ";
        }
        return result;
    }
    finally {
        __leave();
    }
}
function escapeString(string) {
    __enter();
    try {
        string = "" + string;
        let result = "";
        for (let i = 0; i < string.length; i++) {
            __step();
            const code = string.charCodeAt(i);
            if (code === 0)
                throw new InvalidCharacterError("Invalid character: the input contains U+0000.");
            if (between(code, 1, 31) || code === 127)
                result += "\\" + code.toString(16) + " ";
            else if (code === 34 || code === 92)
                result += "\\" + string[i];
            else
                result += string[i];
        }
        return result;
    }
    finally {
        __leave();
    }
}
// packages/isomorphic/cssParser.ts
var InvalidSelectorError = class extends Error {
};
function parseCSS(selector, customNames) {
    __enter();
    try {
        let tokens;
        try {
            tokens = tokenize(selector);
            if (!(tokens[tokens.length - 1] instanceof EOFToken))
                tokens.push(new EOFToken());
        }
        catch (e) {
            if (e === __limit)
                throw e;
            const newMessage = e.message + ` while parsing css selector "${selector}". Did you mean to CSS.escape it?`;
            const index = (e.stack || "").indexOf(e.message);
            if (index !== -1)
                e.stack = e.stack.substring(0, index) + newMessage + e.stack.substring(index + e.message.length);
            e.message = newMessage;
            throw e;
        }
        const unsupportedToken = tokens.find((token) => {
            __enter();
            try {
                return token instanceof AtKeywordToken || token instanceof BadStringToken || token instanceof BadURLToken || token instanceof ColumnToken || token instanceof CDOToken || token instanceof CDCToken || token instanceof SemicolonToken || // TODO: Consider using these for something, e.g. to escape complex strings.
                    // For example :xpath{ (//div/bar[@attr="foo"])[2]/baz }
                    // Or this way :xpath( {complex-xpath-goes-here("hello")} )
                    token instanceof OpenCurlyToken || token instanceof CloseCurlyToken || // TODO: Consider treating these as strings?
                    token instanceof URLToken || token instanceof PercentageToken;
            }
            finally {
                __leave();
            }
        });
        if (unsupportedToken)
            throw new InvalidSelectorError(`Unsupported token "${unsupportedToken.toSource()}" while parsing css selector "${selector}". Did you mean to CSS.escape it?`);
        let pos = 0;
        const names = /* @__PURE__ */ new Set();
        function unexpected() {
            __enter();
            try {
                return new InvalidSelectorError(`Unexpected token "${tokens[pos].toSource()}" while parsing css selector "${selector}". Did you mean to CSS.escape it?`);
            }
            finally {
                __leave();
            }
        }
        function skipWhitespace() {
            __enter();
            try {
                while (tokens[pos] instanceof WhitespaceToken) {
                    __step();
                    pos++;
                }
            }
            finally {
                __leave();
            }
        }
        function isIdent(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof IdentToken;
            }
            finally {
                __leave();
            }
        }
        function isString(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof StringToken;
            }
            finally {
                __leave();
            }
        }
        function isNumber(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof NumberToken;
            }
            finally {
                __leave();
            }
        }
        function isComma(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof CommaToken;
            }
            finally {
                __leave();
            }
        }
        function isOpenParen(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof OpenParenToken;
            }
            finally {
                __leave();
            }
        }
        function isCloseParen(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof CloseParenToken;
            }
            finally {
                __leave();
            }
        }
        function isFunction(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof FunctionToken;
            }
            finally {
                __leave();
            }
        }
        function isStar(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof DelimToken && tokens[p].value === "*";
            }
            finally {
                __leave();
            }
        }
        function isEOF(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof EOFToken;
            }
            finally {
                __leave();
            }
        }
        function isClauseCombinator(p = pos) {
            __enter();
            try {
                return tokens[p] instanceof DelimToken && [">", "+", "~"].includes(tokens[p].value);
            }
            finally {
                __leave();
            }
        }
        function isSelectorClauseEnd(p = pos) {
            __enter();
            try {
                return isComma(p) || isCloseParen(p) || isEOF(p) || isClauseCombinator(p) || tokens[p] instanceof WhitespaceToken;
            }
            finally {
                __leave();
            }
        }
        function consumeFunctionArguments() {
            __enter();
            try {
                const result2 = [consumeArgument()];
                while (true) {
                    __step();
                    skipWhitespace();
                    if (!isComma())
                        break;
                    pos++;
                    result2.push(consumeArgument());
                }
                return result2;
            }
            finally {
                __leave();
            }
        }
        function consumeArgument() {
            __enter();
            try {
                skipWhitespace();
                if (isNumber())
                    return tokens[pos++].value;
                if (isString())
                    return tokens[pos++].value;
                return consumeComplexSelector();
            }
            finally {
                __leave();
            }
        }
        function consumeComplexSelector() {
            __enter();
            try {
                const result2 = { simples: [] };
                skipWhitespace();
                if (isClauseCombinator()) {
                    result2.simples.push({ selector: { functions: [{ name: "scope", args: [] }] }, combinator: "" });
                }
                else {
                    result2.simples.push({ selector: consumeSimpleSelector(), combinator: "" });
                }
                while (true) {
                    __step();
                    skipWhitespace();
                    if (isClauseCombinator()) {
                        result2.simples[result2.simples.length - 1].combinator = tokens[pos++].value;
                        skipWhitespace();
                    }
                    else if (isSelectorClauseEnd()) {
                        break;
                    }
                    result2.simples.push({ combinator: "", selector: consumeSimpleSelector() });
                }
                return result2;
            }
            finally {
                __leave();
            }
        }
        function consumeSimpleSelector() {
            __enter();
            try {
                let rawCSSString = "";
                const functions = [];
                while (!isSelectorClauseEnd()) {
                    __step();
                    if (isIdent() || isStar()) {
                        rawCSSString += tokens[pos++].toSource();
                    }
                    else if (tokens[pos] instanceof HashToken) {
                        rawCSSString += tokens[pos++].toSource();
                    }
                    else if (tokens[pos] instanceof DelimToken && tokens[pos].value === ".") {
                        pos++;
                        if (isIdent())
                            rawCSSString += "." + tokens[pos++].toSource();
                        else
                            throw unexpected();
                    }
                    else if (tokens[pos] instanceof ColonToken) {
                        pos++;
                        if (isIdent()) {
                            if (!customNames.has(tokens[pos].value.toLowerCase())) {
                                rawCSSString += ":" + tokens[pos++].toSource();
                            }
                            else {
                                const name = tokens[pos++].value.toLowerCase();
                                functions.push({ name, args: [] });
                                names.add(name);
                            }
                        }
                        else if (isFunction()) {
                            const name = tokens[pos++].value.toLowerCase();
                            if (!customNames.has(name)) {
                                rawCSSString += `:${name}(${consumeBuiltinFunctionArguments()})`;
                            }
                            else {
                                functions.push({ name, args: consumeFunctionArguments() });
                                names.add(name);
                            }
                            skipWhitespace();
                            if (!isCloseParen())
                                throw unexpected();
                            pos++;
                        }
                        else {
                            throw unexpected();
                        }
                    }
                    else if (tokens[pos] instanceof OpenSquareToken) {
                        rawCSSString += "[";
                        pos++;
                        while (!(tokens[pos] instanceof CloseSquareToken) && !isEOF()) {
                            __step();
                            rawCSSString += tokens[pos++].toSource();
                        }
                        if (!(tokens[pos] instanceof CloseSquareToken))
                            throw unexpected();
                        rawCSSString += "]";
                        pos++;
                    }
                    else {
                        throw unexpected();
                    }
                }
                if (!rawCSSString && !functions.length)
                    throw unexpected();
                return { css: rawCSSString || void 0, functions };
            }
            finally {
                __leave();
            }
        }
        function consumeBuiltinFunctionArguments() {
            __enter();
            try {
                let s = "";
                let balance = 1;
                while (!isEOF()) {
                    __step();
                    if (isOpenParen() || isFunction())
                        balance++;
                    if (isCloseParen())
                        balance--;
                    if (!balance)
                        break;
                    s += tokens[pos++].toSource();
                }
                return s;
            }
            finally {
                __leave();
            }
        }
        const result = consumeFunctionArguments();
        if (!isEOF())
            throw unexpected();
        if (result.some((arg) => {
            __enter();
            try {
                return typeof arg !== "object" || !("simples" in arg);
            }
            finally {
                __leave();
            }
        }))
            throw new InvalidSelectorError(`Error while parsing css selector "${selector}". Did you mean to CSS.escape it?`);
        return { selector: result, names: Array.from(names) };
    }
    finally {
        __leave();
    }
}
var customCSSNames = /* @__PURE__ */ new Set(["not", "is", "where", "has", "scope", "light", "visible", "text", "text-matches", "text-is", "has-text", "above", "below", "right-of", "left-of", "near", "nth-match"]);

return function parseRawCss(source) {
 if(typeof source!=='string')throw new TypeError('CSS source must be a string');
 let bytes=0;for(let i=0;i<source.length;i++){__step();const c=source.charCodeAt(i);if(c<128)bytes++;else if(c<2048)bytes+=2;else if(c>=0xd800&&c<=0xdbff&&source.charCodeAt(i+1)>=0xdc00&&source.charCodeAt(i+1)<=0xdfff){bytes+=4;i++;__step();}else bytes+=3;if(bytes>65536)throw __limit;}
 return parseCSS(source,customCSSNames);
};
}
