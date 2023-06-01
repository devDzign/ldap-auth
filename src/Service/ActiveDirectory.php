<?php

namespace App\Service;

use Symfony\Component\Ldap\Adapter\ExtLdap\Adapter;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Ldap;

class ActiveDirectory
{
    public function __construct(
        private Adapter $ldapAdapter,
        private Ldap $ldap,
        private string $ldapServiceDn,
        private string $ldapServiceUser,
        private string $ldapServicePassword,
    ) {
        $this->ldap = new Ldap($this->ldapAdapter);
        $this->ldap->bind(implode(',', [$ldapServiceUser, $ldapServiceDn]), $ldapServicePassword);
    }

    // Récupère un utilisateur AD via le LDAP à partir des informations envoyées
    public function getEntryFromActiveDirectory(string $username, string $password): ?Entry
    {
        $ldap = new Ldap($this->ldapAdapter);
        $search = false;
        $value = null;


        try {
            $ldap->bind(implode(',', ['cn=admin', $this->ldapServiceDn]), 'admin');

            if ($this->ldapAdapter->getConnection()->isBound()) {
                $search = $ldap->query(
                    'dc=ramhlocal,dc=com',
                    '(&(objectClass=*) (cn='.$username.')(userPassword='.$password.'))'
                )->execute()->toArray();
            }
        } catch (ConnectionException $e) {
            dd($e);
            return null;
        }

        dd($search);
        if ($search && 1 === count($search)) {
            $value = $search[0];
        }
        return $value;
    }
}
