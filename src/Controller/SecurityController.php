<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SecurityController extends AbstractController
{
    #[Route('/security', name: 'login', methods: ['POST'])]
        public function login(): Response
    {
        /* THIS CONTROLLER NEVER RESPOND */
        return $this->json('', Response::HTTP_OK);
    }

}


