<?php

/**
 * @author    Yuriy Davletshin <yuriy.davletshin@gmail.com>
 * @copyright 2017 Yuriy Davletshin
 * @license   MIT
 */

declare(strict_types=1);

namespace Satori\Middleware\SimpleAuth;

use Satori\Application\ApplicationInterface;
use Satori\Http\{Request, Session};

/**
 * Initializes the SimpleAuth middleware.
 *
 * @param ApplicationInterface  $app   The application.
 * @param string                $id    The unique name of the middleware.
 * @param array<string, string> $names
 *    The array with names
 *      ```
 *      [
 *          'login_action' => 'loginAction',
 *          'auth_action' => 'authAction',
 *          'login_path' => 'login_path',
 *          'session_lifetime' => 'session.lifetime',
 *          'session_path' => 'session.path',
 *          'session_domain' => 'session.domain',
 *          'session_secure' => 'session.secure',
 *          'session_httponly' => 'session.httponly'
 *      ]
 *      ```
 *      .
 */
function init(ApplicationInterface $app, string $id, array $names)
{
    $app[$id] = function (\Generator $next) use ($app, $names) {
        $app->notify('start_auth');
        $capsule = yield;
        $capsule['action'] = $capsule['action'] ?? '';
        $loginAction = $names['login_action'];
        $authAction = $names['auth_action'];
        $loginPath = $app[$names['login_path'] ?? ''] ?? '/login';
        $lifetime = $app[$names['session_lifetime'] ?? ''] ?? 1440;
        $path = $app[$names['session_path'] ?? ''] ?? '/';
        $domain = $app[$names['session_domain'] ?? ''] ?? '';
        $secure = $app[$names['session_secure'] ?? ''] ?? false;
        $httponly = $app[$names['session_httponly'] ?? ''] ?? true;
        $login = $capsule['action'] === $loginAction || $capsule['action'] === $authAction;
        session_set_cookie_params($lifetime, $path, $domain, $secure, $httponly);
        Session\start();
        $validIp = Session\get('user.ip') === $_SERVER['REMOTE_ADDR'];
        if ((Session\has('user.name') and $validIp) or $login) {
            if (!$login) {
                Session\remove('last');
            }
            Session\release();
            $app->notify('finish_auth');
            $next->send($capsule);

            return $next->getReturn();
        }
        if ($capsule['action']) {
            Session\set('last', Request\getUri());
        }
        Session\release();
        $capsule['action'] = '';
        $capsule['http.status'] = 303;
        $capsule['http.headers'] = ['Location' => $loginPath];
        $app->notify('finish_auth');
        $next->send($capsule);

        return $capsule;
    };
}
