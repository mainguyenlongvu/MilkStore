using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MilkStore.Repositories.Migrations
{
    /// <inheritdoc />
    public partial class fixTransactionHistory : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_TransactionHistories_Users_UserId",
                table: "TransactionHistories");

            migrationBuilder.DropIndex(
                name: "IX_TransactionHistories_UserId",
                table: "TransactionHistories");

            migrationBuilder.AddColumn<Guid>(
                name: "ApplicationUserId",
                table: "TransactionHistories",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_TransactionHistories_ApplicationUserId",
                table: "TransactionHistories",
                column: "ApplicationUserId");

            migrationBuilder.AddForeignKey(
                name: "FK_TransactionHistories_Users_ApplicationUserId",
                table: "TransactionHistories",
                column: "ApplicationUserId",
                principalTable: "Users",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_TransactionHistories_Users_ApplicationUserId",
                table: "TransactionHistories");

            migrationBuilder.DropIndex(
                name: "IX_TransactionHistories_ApplicationUserId",
                table: "TransactionHistories");

            migrationBuilder.DropColumn(
                name: "ApplicationUserId",
                table: "TransactionHistories");

            migrationBuilder.CreateIndex(
                name: "IX_TransactionHistories_UserId",
                table: "TransactionHistories",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_TransactionHistories_Users_UserId",
                table: "TransactionHistories",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
