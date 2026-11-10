<?php
// T42, IDP-40, OP-155 m.3 (q), Ek B 5100
declare(strict_types=1);

require '/tmp/sp/vendor/autoload.php';

use RobRichards\XMLSecLibs\XMLSecurityKey;

function env_of(string $dir): array
{
    $out = [];
    foreach (file("$dir/expected.env", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        [$k, $v] = explode('=', $line, 2);
        $out[$k] = $v;
    }
    return $out;
}

function key_of(string $dir): XMLSecurityKey
{
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);
    $key->loadKey(file_get_contents("$dir/idp.pem"), false, true);
    return $key;
}

function accept(string $file, XMLSecurityKey $key, array $env): void
{
    $doc = \SAML2\DOMDocumentFactory::fromFile($file);
    $response = new \SAML2\Response($doc->documentElement);
    if (!$response->isSuccess()) {
        throw new Exception('status is not Success');
    }
    if ($response->getDestination() !== $env['ACS']) {
        throw new Exception('Destination is not the ACS');
    }
    if ($response->getInResponseTo() !== $env['REQUEST_ID']) {
        throw new Exception('InResponseTo does not match');
    }
    $responseSigned = $response->validate($key);
    $assertions = $response->getAssertions();
    if (count($assertions) !== 1 || !($assertions[0] instanceof \SAML2\Assertion)) {
        throw new Exception('expected one plaintext assertion');
    }
    $a = $assertions[0];
    $assertionSigned = $a->validate($key);
    if (!$responseSigned && !$assertionSigned) {
        throw new Exception('neither the response nor the assertion is signed');
    }
    if ($a->getIssuer()->getValue() !== $env['IDP_ENTITY']) {
        throw new Exception('assertion issuer');
    }
    if (!in_array($env['SP_ENTITY'], $a->getValidAudiences() ?? [], true)) {
        throw new Exception('audience');
    }
    if ($a->getNotOnOrAfter() !== null && $a->getNotOnOrAfter() <= time()) {
        throw new Exception('assertion expired');
    }
    $confirmed = false;
    foreach ($a->getSubjectConfirmation() as $sc) {
        $data = $sc->getSubjectConfirmationData();
        if ($sc->getMethod() === \SAML2\Constants::CM_BEARER && $data !== null
            && $data->getRecipient() === $env['ACS'] && $data->getNotOnOrAfter() > time()) {
            $confirmed = true;
        }
    }
    if (!$confirmed) {
        throw new Exception('no valid bearer subject confirmation');
    }
    if ($a->getNameId() === null || $a->getNameId()->getValue() === '') {
        throw new Exception('no NameID');
    }
}

$dir = $argv[1];
$env = env_of($dir);
$key = key_of($dir);
accept("$dir/response.xml", $key, $env);
echo "SimpleSAMLphp accepts the real response\n";
try {
    accept("$dir/tampered.xml", $key, $env);
    fwrite(STDERR, "SimpleSAMLphp accepted the tampered response\n");
    exit(1);
} catch (Throwable $e) {
    echo "SimpleSAMLphp refuses the tampered response: {$e->getMessage()}\n";
}
