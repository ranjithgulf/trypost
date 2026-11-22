<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Zoho Directory subject (`sub`) of a linked account. Additive and
     * nullable, so existing rows and older application images are unaffected.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->string('zoho_id')->nullable()->unique()->after('github_id');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->dropColumn('zoho_id');
        });
    }
};
