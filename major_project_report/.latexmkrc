# Build config for the Major Project Report (pdflatex + biblatex/bibtex + glossaries).
# Engine: pdflatex (book class, no fontspec). SyncTeX on so Skim maps PDF <-> source.
$pdf_mode = 1;
$pdflatex = 'pdflatex -synctex=1 -interaction=nonstopmode -file-line-error %O %S';

# Preview in Skim (used by `latexmk -pvc`). Skim auto-reloads when the PDF is rewritten.
$pdf_previewer = 'open -a Skim';

# Glossaries / acronyms: latexmk won't run makeglossaries on its own, so register it
# as a custom dependency keyed off the .aux file (standard latexmk snippet).
add_cus_dep('glo', 'gls', 0, 'run_makeglossaries');
add_cus_dep('acn', 'acr', 0, 'run_makeglossaries');
# Custom glossary 'sym' (List of Symbols) declared via \newglossary[sym]{symbolList}{sym1}{sym2}
add_cus_dep('sym1', 'sym2', 0, 'run_makeglossaries');

sub run_makeglossaries {
    my ($base_name, $path) = fileparse($_[0]);
    pushd($path);
    my $return = system "makeglossaries", $base_name;
    popd();
    return $return;
}

# Make sure makeglossaries-generated files are cleaned by `latexmk -C`.
push @generated_exts, 'glo', 'gls', 'glg';
push @generated_exts, 'acn', 'acr', 'alg';
push @generated_exts, 'sym1', 'sym2', 'slg';
push @generated_exts, 'synctex.gz';
