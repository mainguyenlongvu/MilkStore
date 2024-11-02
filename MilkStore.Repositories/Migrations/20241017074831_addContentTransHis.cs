using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MilkStore.Repositories.Migrations
{
    /// <inheritdoc />
    public partial class addContentTransHis : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Content",
                table: "TransactionHistories",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Content",
                table: "TransactionHistories");
        }
    }
}
