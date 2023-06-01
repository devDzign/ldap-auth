<?php

namespace App\Security;

use App\Entity\User;
use App\Exception\CustomBadRequestException;
use App\Exception\CustomUnsupportedMediaTypeException;
use App\Repository\UserRepository;
use App\Service\ActiveDirectory;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTNotFoundEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTEncodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\MissingTokenException;
use Lexik\Bundle\JWTAuthenticationBundle\Response\JWTAuthenticationFailureResponse;
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


class CustomLdapAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
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
        if ('json' !== $request->getContentTypeFormat() || null === $request->getContentTypeFormat()) {
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
            } else { /* SI OUI, ON METS UNIQUEMENT A JOUR SA DATE DE DERNIERE CONNEXION */
                $userFromRepo->setLastLogin(new \DateTime());
                $this->entityManager->persist($userFromRepo);
            }
            $this->entityManager->flush();
        }
        /* SI TOUT S'EST BIEN PASSE ON RENVOIE UN BADGE AUTORISÉ A PASSER DANS SYMFONY */
        return new SelfValidatingPassport(new UserBadge($loginFromRequest));
    }

    /* CETTE FONCTION EST APPELLÉE SI L'AUTHENTIFICATION A RÉUSSIE */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        /* ON RECUPERE LES ROLES DE L'UTILISATEUR A PARTIR DE LA BDD */
        try {
            $user = $this->userRepository->findOneBy(['login' => $token->getUserIdentifier()]);
            /* RECUPERE LES ROLES DE L'UTILISATEUR */
            if (null !== $user) {
                $roles = $user->getRoles();
            } else {
                $roles = null;
            }

            /* ON GENERE LE TOKEN AVEC UNE DUREE DE VIE DE 1200s (20mn) */
            $jwtToken = $this->encoder->encode(['username' => $token->getUserIdentifier(), 'roles' => $roles, 'id' => $user->getId(), 'exp' => time() + 1200]);

            /* ON VA VERIFIER QU'UN REFRESH_TOKEN N'EXISTE PAS DEJA ET SI C'EST LE CAS ON LE RETIRE */

            $refreshToken = $this->refreshTokenManager->getLastFromUsername($token->getUserIdentifier());
            if( null !== $refreshToken) {
                $this->refreshTokenManager->delete($refreshToken);
            }

            /* ON GENERE LE REFRESH TOKEN AVEC UNE DUREE DE VIE DE 30 JOURS */
            $refreshToken = $this->refreshTokenGenerator->createForUserWithTtl($token->getUser(), 2592000);

            /* ON PERSISTE LE REFRESH TOKEN EN BASE */
            $this->entityManager->persist($refreshToken);

            /* ON ENREGISTRE TOUS LES TOKENS */
            $this->entityManager->flush();
        } catch (JWTEncodeFailureException $JWTEncodeFailureException) {
            return new JsonResponse(['message' => $JWTEncodeFailureException->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        } catch (\Exception $e) {
            return new JsonResponse(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        /* ON RENVOIE LE TOKEN A L'UTILISATEUR */
        return new JsonResponse(['token' => $jwtToken, 'refresh_token' => $refreshToken->getRefreshToken()], Response::HTTP_CREATED);
    }

    /* CETTE FONCTION EST APPELLEE SI L'AUTHENTIFICATION A ÉCHOUÉE */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        /* ON GENERE L'ERREUR DE FACON DYNAMIQUE */
        if ($exception instanceof CustomUnsupportedMediaTypeException) {
            $codeResponse = Response::HTTP_UNSUPPORTED_MEDIA_TYPE;
        } elseif ($exception instanceof CustomBadRequestException) {
            $codeResponse = Response::HTTP_BAD_REQUEST;
        } elseif ($exception instanceof UserNotFoundException) {
            $codeResponse = Response::HTTP_NOT_FOUND;
        } else {
            $codeResponse = Response::HTTP_UNAUTHORIZED;
        }
        $data = [
            /* ON RECUPERE LE MESSAGE D'EXCEPTION */
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
        ];

        /* ON RETOURNE LE MESSAGE D'ERREUR A L'UTILISATEUR */
        return new JsonResponse($data, $codeResponse);
    }

    /* CETTE FONCTION EST APPELLÉE SI L'UTILISATEUR CONSOMME UNE ROUTE PROTEGEE, SANS FOURNIR D'INFORMATION D'AUTHENTIFICATION */
    public function start(Request $request, AuthenticationException $authException = null): ?Response
    {
        $exception = new MissingTokenException('JWT Token not found', 0, $authException);
        $event = new JWTNotFoundEvent($exception, new JWTAuthenticationFailureResponse($exception->getMessageKey()));
        return $event->getResponse();
    }
}


