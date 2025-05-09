<?php

namespace Database\Seeders;

use App\Models\Role;
use Illuminate\Database\Seeder;

class RoleSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $roles = [
            [
                'name' => 'admin',
                'description' => 'Administrator with full access to manage the application'
            ],
            [
                'name' => 'couple',
                'description' => 'Bride and groom who are planning their wedding'
            ],
            [
                'name' => 'vendor',
                'description' => 'Wedding service providers (photographers, caterers, venues, etc.)'
            ],
            [
                'name' => 'guest',
                'description' => 'Wedding guests who can RSVP and view event details'
            ],
        ];

        foreach ($roles as $role) {
            Role::create($role);
        }
    }
}
