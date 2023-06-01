<?php

namespace App\Security;

use App\Entity\User;
use App\Exception\CustomBadRequestException;
use App\Exception\CustomUnsupportedMediaTypeException;
use App\Repository\UserRepository;
use App\Service\ActiveDirectory;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Gesdinet\JWTRefreshTokenBundle\Generator\RefreshTokenGeneratorInterface;
use Gesdinet\JWTRefreshTokenBundle\Model\RefreshTokenManagerInterface;
class CustomLdpAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{

    /* AUTOWIRING DES OBJETS PAR SYMFONY */
    public function __construct(
        private ActiveDirectory $activeDirectory,
        private JWTEncoderInterface $encoder,
        private UserRepository $userRepository,
        private EntityManagerInterface $entityManager,
        private RefreshTokenGeneratorInterface $refreshTokenGenerator,
        private RefreshTokenManagerInterface $refreshTokenManager)
    {}

    /* CETTE FONCTION EST APPELLE POUR CHAQUE REQUÊTE, C'EST A NOUS DE DÉCIDER SI ON APPLIQUE LE CONTRÔLE D'IDENTIFICATION OU NON */
    public function supports(Request $request): ?bool
    {
        /* TEST SI LA ROUTE est /login A PARTIR DE L'API  && SI LA METHODE EST DE TYPE POST
			-> SI C'EST LE CAS, ON DECLENCHE L'AUTHENTIFICATION,
			-> SINON, ON IGNORE L'AUTHENTICATOR
	*/
        return 'login' === $request->attributes->get('_route') && $request->isMethod(Request::METHOD_POST);
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        /* TEST SI LE CONTENT-TYPE EST OK */
        if ('json' != $request->getContentTypeFormat() || null == $request->getContentTypeFormat()) {
            throw new CustomUnsupportedMediaTypeException('WRONG CONTENT-TYPE');
        }

        /* ON RECUPERE LES INFOS A PARTIR DU CORPS DE LA REQUÊTE */
        $body = json_decode($request->getContent(), false, 512, JSON_THROW_ON_ERROR);
        if (!isset($body->password, $body->username) || null === $body->username || null === $body->password) {
            throw new CustomBadRequestException('ERROR IN REQUEST');
        }

        $loginFromRequest = $body->username;
        $passwordFromRequest = $body->password;

        /* RECUPERE L'UTILISATEUR DANS LE LDAP (AUTHENTIFIE AU PASSAGE L'UTILISATEUR) */
        $ldapEntry = $this->activeDirectory->getEntryFromActiveDirectory($loginFromRequest, $passwordFromRequest);

        if (null === $ldapEntry) { /* SI ON NE RECUPERE RIEN */
            throw new UserNotFoundException('IMPOSSIBLE TO RETRIEVE THE RESOURCE'); /* ON RENVOIE UN ERREUR D'AUTHENTIFICATION */
        } else { /* SINON L'UTILISATEUR EXISTE DANS LE LDAP */
            $userFromRepo = $this->userRepository->findOneBy(['login' => $loginFromRequest]);  /* ON VERIFIE QU'IL EXISTE EN BDD */
            if (null === $userFromRepo) { /* SI NON ON LE CREE */
                $userToPersist = new User();
                $userToPersist->setLogin($loginFromRequest);
                try {
                    $userToPersist->setRoles(['ROLE_USER']);
                    $userToPersist->setLastLogin(new \DateTime());
                    $userToPersist->setIsActive(true);
                } catch (\InvalidArgumentException) {
                    throw new AuthenticationException();
                }
                $this->entityManager->persist($userToPersist);
            }
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new JsonResponse('');
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse('');
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        // TODO: Implement start() method.
    }
}
