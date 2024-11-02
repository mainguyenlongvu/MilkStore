using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MilkStore.Repositories.Migrations
{
    /// <inheritdoc />
    public partial class deleteTransactionHistories : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_TransactionHistories_Users_ApplicationUserId",
                table: "TransactionHistories");

            migrationBuilder.DropPrimaryKey(
                name: "PK_TransactionHistories",
                table: "TransactionHistories");

            migrationBuilder.RenameTable(
                name: "TransactionHistories",
                newName: "TransactionHistory");

            migrationBuilder.RenameIndex(
                name: "IX_TransactionHistories_ApplicationUserId",
                table: "TransactionHistory",
                newName: "IX_TransactionHistory_ApplicationUserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_TransactionHistory",
                table: "TransactionHistory",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_TransactionHistory_Users_ApplicationUserId",
                table: "TransactionHistory",
                column: "ApplicationUserId",
                principalTable: "Users",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_TransactionHistory_Users_ApplicationUserId",
                table: "TransactionHistory");

            migrationBuilder.DropPrimaryKey(
                name: "PK_TransactionHistory",
                table: "TransactionHistory");

            migrationBuilder.RenameTable(
                name: "TransactionHistory",
                newName: "TransactionHistories");

            migrationBuilder.RenameIndex(
                name: "IX_TransactionHistory_ApplicationUserId",
                table: "TransactionHistories",
                newName: "IX_TransactionHistories_ApplicationUserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_TransactionHistories",
                table: "TransactionHistories",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_TransactionHistories_Users_ApplicationUserId",
                table: "TransactionHistories",
                column: "ApplicationUserId",
                principalTable: "Users",
                principalColumn: "Id");
        }
    }
}
