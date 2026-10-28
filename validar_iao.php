<?php
declare(strict_types=1);

$local = 'http://127.0.0.1:8080/';

// Introduce la URL HTTPS de Cloudflare como argumento.
// No se presupone que el túnel ya esté funcionando.
$publica = $argv[1] ?? '';

function comprobar(string $nombre, string $url): void {
    echo "\n=== $nombre ===\n";

    if (!filter_var($url, FILTER_VALIDATE_URL) ||
        !in_array(parse_url($url, PHP_URL_SCHEME), ['http', 'https'], true)) {
        echo "RESULTADO: URL no válida\n";
        return;
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'IAO-Diagnostic/1.0',
    ]);

    $body = curl_exec($ch);
    $error = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $tiempo = (float) curl_getinfo($ch, CURLINFO_TOTAL_TIME);

    if ($body === false) {
        echo "RESULTADO: ERROR DE CONEXIÓN\n";
        echo "Detalle: $error\n";
        return;
    }

    echo "HTTP: $status\n";
    echo "Tiempo: " . round($tiempo * 1000) . " ms\n";
    echo "Bytes recibidos: " . strlen($body) . "\n";

    if ($status >= 200 && $status < 300) {
        echo "RESULTADO: RESPUESTA HTTP CORRECTA\n";
    } elseif ($status >= 300 && $status < 400) {
        echo "RESULTADO: REDIRECCIÓN; requiere revisión\n";
    } else {
        echo "RESULTADO: RESPUESTA HTTP NO SATISFACTORIA\n";
    }

    // Indicador auxiliar; no demuestra por sí solo
    // que la IA genere respuestas cognitivas.
    if (stripos($body, 'IAO') !== false ||
        stripos($body, 'SO-OMEGA PRIME') !== false) {
        echo "IDENTIDAD: aparece un nombre del proyecto en la respuesta\n";
    } else {
        echo "IDENTIDAD: no confirmada por el contenido de la página\n";
    }
}

echo "DIAGNÓSTICO DE CONECTIVIDAD DE IAO\n";
comprobar('SERVIDOR LOCAL', $local);

if ($publica !== '') {
    if (parse_url($publica, PHP_URL_SCHEME) !== 'https') {
        echo "\nLa URL pública debe usar HTTPS.\n";
        exit(2);
    }
    comprobar('ACCESO PÚBLICO POR INTERNET', $publica);
} else {
    echo "\nPrueba pública pendiente: falta la URL HTTPS de Cloudflare.\n";
}
