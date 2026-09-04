TypeScript Frontend
===================

The TypeScript frontend is independent from the JavaScript parser. It loads a
TypeScript project, parses original source with ``typescript-estree``, queries
the TypeScript checker, performs analysis-oriented runtime normalization, and
emits the same tab-separated graph contract consumed by the Python engine.
TypeScript is not emitted as JavaScript.

Frontend boundary
-----------------

``probejs.core.esprima.esprima_parse`` selects ``main.js`` for JavaScript and
``typescript-main.js`` for ``.ts``, ``.tsx``, ``.mts``, ``.cts``, and explicit
TypeScript stdin. The TypeScript coordinator owns reachable TypeScript files.
Resolved JavaScript implementations and probejs model files are emitted by the
unchanged JavaScript frontend and merged using disjoint node-ID ranges.

CSV contract
------------

The node table begins with ``id:ID`` and the relationship table begins with
``start:START_ID``, ``end:END_ID``, and ``type:TYPE``. The tables are separated
by one blank line when transported through stdout.

Every runtime source file has:

* a ``Filesystem``/``File`` node whose ``name`` is its absolute path;
* an ``AST_TOPLEVEL`` child connected by ``FILE_OF``;
* one ``ENTRY`` and one ``EXIT`` artificial child;
* an ``AST_STMT_LIST`` containing runtime statements in source order.

``childnum:int`` defines ordered AST children and ``funcid:int`` associates
nodes with their enclosing function or top level. The TypeScript frontend uses
the same ``AST_*`` operation types and flags as the JavaScript frontend, so the
Python operation generator requires no language-specific dispatch.

Original nodes retain their source line, column, range, and source slice.
Analysis-only nodes are marked with ``generated:bool`` and an origin location.
Generated nodes include module bindings, enum properties, parameter-property
assignments, class-field initializers, decorator calls, and entrypoint calls.

Normalization
-------------

Interfaces, type aliases, ambient declarations, overload signatures, and
type-only imports/exports have no runtime nodes. Assertions, ``satisfies``,
non-null expressions, and type instantiations delegate to their runtime
expression. Enums, namespaces, parameter properties, class fields, decorators,
TSX, and TypeScript import/export assignments are converted directly to small
runtime graph shapes; compiler helper functions are never introduced.

Semantic metadata
-----------------

Parser services provide an exact mapping from each ESTree call to its
TypeScript node. Resolved overloads and instantiated signatures populate the
existing callback, callback-property, return-type, and promise-like columns.
Type information adds conservative call behavior and never removes a runtime
flow. Syntax, configuration, option, and semantic diagnostics are attached to
file rows and collected in ``report.json``.

ArkTS
-----

ArkTS ``.ets`` is not TypeScript and is not normalized heuristically. Users
must compile it with the matching HarmonyOS toolchain and analyze the generated
JavaScript.
