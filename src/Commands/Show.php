<?php

namespace Spatie\Permission\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Spatie\Permission\Models\Module;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class Show extends Command
{
    protected $signature = 'permission:show
            {guard? : The name of the guard}
            {style? : The display style (default|borderless|compact|box)}';

    protected $description = 'Show a table of roles, modules and permissions per guard';

    public function handle()
    {
        $style = $this->argument('style') ?? 'default';
        $guard = $this->argument('guard');

        if ($guard) {
            $guards = Collection::make([$guard]);
        } else {
            $guards = Permission::pluck('guard_name')->merge(Module::pluck('guard_name'))->merge(Role::pluck('guard_name'))->unique();
        }

        foreach ($guards as $guard) {
            $this->info("Guard: $guard");

            $roles = Role::whereGuardName($guard)->orderBy('name')->get()->mapWithKeys(function (Role $role) {
                return [$role->name => $role->permissions->pluck('name')];
            });
            
            $modules = Module::whereGuardName($guard)->orderBy('name')->get()->mapWithKeys(function (Module $module) {
                return [$module->name => $module->permissions->pluck('name')];
            });

            $permissions = Permission::whereGuardName($guard)->orderBy('name')->pluck('name');

            $body1 = $permissions->map(function ($permission) use ($roles) {
                return $roles->map(function (Collection $role_permissions) use ($permission) {
                    return $role_permissions->contains($permission) ? ' ✔' : ' ·';
                })->prepend($permission);
            });

            $body2 = $permissions->map(function ($permission) use ($modules) {
                $modules->map(function (Collection $module_permissions) use ($permission) {
                    return $module_permissions->contains($permission) ? ' ✔' : ' ·';
                })->prepend($permission);
            });

            $body = array_merge($body1, $body2);

            $this->table(
                $roles->keys()->prepend('')->toArray(),
                $body->toArray(),
                $style
            );
        }
    }
}
