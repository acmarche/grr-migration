<?php
/**
 * This file is part of GrrSf application.
 *
 * @author jfsenechal <jfsenechal@gmail.com>
 * @date 6/09/19
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Grr\Migration;

use Exception;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class RequestData
{
    /**
     * @var HttpClientInterface
     */
    private $httpClient;
    /**
     * @var string
     */
    private $base_url;
    /**
     * @var MigrationUtil
     */
    private $migrationUtil;

    public function __construct(MigrationUtil $migrationUtil)
    {
        $this->migrationUtil = $migrationUtil;
    }

    private function setBaseUrl(string $url): void
    {
        $url = rtrim($url, '/');
        $this->base_url = $url.DIRECTORY_SEPARATOR.'migration'.DIRECTORY_SEPARATOR;
    }

    public function connect(string $url, string $user, string $password): void
    {
        $this->setBaseUrl($url);
        $options = [
            'auth_basic' => [$user, $password],
            'http_version' => '1.1',
        ];
        $this->httpClient = HttpClient::create($options);
    }

    /**
     * @return string|bool
     */
    public function getEntries(array $params = []): string
    {
        return $this->request('entry.php', $params);
    }

    /**
     * @return string|bool
     */
    public function getAreas(): string
    {
        return $this->request('area.php');
    }

    /**
     * @return string|bool
     */
    public function getRooms(): string
    {
        return $this->request('room.php');
    }

    /**
     * @return string|bool
     */
    public function getUsers(): string
    {
        return $this->request('user.php');
    }

    /**
     * @return string|bool
     */
    public function getTypesEntry(): string
    {
        return $this->request('type.php');
    }

    /**
     * @return string|bool
     */
    public function getAreaAdmin(): string
    {
        return $this->request('user_admin_area.php');
    }

    /**
     * @return string|bool
     */
    public function getRoomAdmin(): string
    {
        return $this->request('user_room.php');
    }

    public function download(string $url, array $params = []): string
    {
        $jsonfile = str_replace('php', 'json', $url);

        $args = [
            'buffer' => false,
        ];

        if (count($params) > 0) {
            $args['query'] = $params;
        }

        try {
            $response = $this->httpClient->request('GET', $this->base_url.$url, $args);
        } catch (TransportExceptionInterface $e) {
            return json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR, 512);
        }

        try {
            if (200 !== $response->getStatusCode()) {
                return json_encode(
                    ['error' => 'Code erreur request'.$response->getStatusCode()],
                    JSON_THROW_ON_ERROR,
                    512
                );
            }
        } catch (TransportExceptionInterface $e) {
            return json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR, 512);
        }

        $fileHandler = fopen($this->migrationUtil->getCacheDirectory().$jsonfile, 'wb');

        foreach ($this->httpClient->stream($response) as $chunk) {
            try {
                fwrite($fileHandler, $chunk->getContent());
            } catch (TransportExceptionInterface $e) {
                return json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR, 512);
            }
        }
        fclose($fileHandler);

        try {
            $this->checkDownload($jsonfile);
        } catch (Exception $e) {
            return json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR, 512);
        }

        return json_encode([], JSON_THROW_ON_ERROR);
    }

    /**
     * @return false|string
     */
    private function request(string $file, array $params = []): string
    {
        // don't want to buffer the response in memory
        $args = [
            'buffer' => false,
        ];

        if (count($params) > 0) {
            $args['query'] = $params;
        }

        try {
            $response = $this->httpClient->request('GET', $this->base_url.$file, $args);
            try {
                return $response->getContent();
            } catch (ClientExceptionInterface $e) {
                return json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR, 512);
            } catch (RedirectionExceptionInterface $e) {
                return json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR, 512);
            } catch (ServerExceptionInterface $e) {
                return json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR, 512);
            } catch (TransportExceptionInterface $e) {
                return json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR, 512);
            }
        } catch (TransportExceptionInterface $e) {
            return json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR, 512);
        }
    }

    /**
     * @param $jsonfile
     *
     * @throws \Exception
     */
    private function checkDownload($jsonfile): void
    {
        $data = json_decode(file_get_contents($this->migrationUtil->getCacheDirectory().$jsonfile), true, 512, JSON_THROW_ON_ERROR);

        if (isset($data['error'])) {
            throw new Exception($data['error']);
        }
    }
}
