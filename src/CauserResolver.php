<?php

namespace Spatie\Activitylog;

use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Spatie\Activitylog\Exceptions\CouldNotLogActivity;

class CauserResolver
{
    protected AuthManager $authManager;

    protected string | null $authDriver;

    protected Closure | null $resolverOverride = null;

    protected Authenticatable | null $causerOverride = null;

    public function __construct(Repository $config, AuthManager $authManager)
    {
        $this->authManager = $authManager;

        $this->authDriver = $config['activitylog']['default_auth_driver'];
    }

    public function resolve(Authenticatable | int | string | null $subject = null): ?Authenticatable
    {
        if ($this->causerOverride !== null) {
            return $this->causerOverride;
        }

        if ($this->resolverOverride !== null) {
            $resultCauser = ($this->resolverOverride)($subject);

            if (! $this->isResolvable($resultCauser)) {
                throw CouldNotLogActivity::couldNotDetermineUser($resultCauser);
            }

            return $resultCauser;
        }

        return $this->getCauser($subject);
    }

    protected function resolveUsingId(int | string $subject): Authenticatable
    {
        $guard = $this->authManager->guard($this->authDriver);

        $provider = method_exists($guard, 'getProvider') ? $guard->getProvider() : null;
        $Authenticatable = method_exists($provider, 'retrieveById') ? $provider->retrieveById($subject) : null;

        throw_unless($Authenticatable instanceof Authenticatable, CouldNotLogActivity::couldNotDetermineUser($subject));

        return $Authenticatable;
    }

    protected function getCauser(Authenticatable | int | string | null $subject = null): ?Authenticatable
    {
        if ($subject instanceof Authenticatable) {
            return $subject;
        }

        if (is_null($subject)) {
            return $this->getDefaultCauser();
        }

        return $this->resolveUsingId($subject);
    }

    /**
     * Override the resover using callback.
     */
    public function resolveUsing(Closure $callback): static
    {
        $this->resolverOverride = $callback;

        return $this;
    }

    /**
     * Override default causer.
     */
    public function setCauser(?Authenticatable $causer): static
    {
        $this->causerOverride = $causer;

        return $this;
    }

    protected function isResolvable(mixed $Authenticatable): bool
    {
        return $Authenticatable instanceof Authenticatable || is_null($Authenticatable);
    }

    protected function getDefaultCauser(): ?Authenticatable
    {
        return $this->authManager->guard($this->authDriver)->user();
    }
}
