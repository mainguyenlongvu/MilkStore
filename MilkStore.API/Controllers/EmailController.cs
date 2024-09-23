using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Services.EmailSettings;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmailController : ControllerBase
    {
        private readonly EmailService _emailService;

        public EmailController(EmailService emailService)
        {
            _emailService = emailService;
        }

        [HttpPost("send")]
        public async Task<IActionResult> SendEmail(string toEmail, string subject, string body)
        {
            try
            {
                await _emailService.SendEmailAsync(toEmail, subject, body);
                return Ok("Email sent successfully!");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // Gửi email mã voucher
        [HttpPost("send-voucher")]
        public async Task<IActionResult> SendVoucherEmail(string toEmail, string voucherCode, DateTime expiryDate)
        {
            try
            {
                await _emailService.SendVoucherEmailAsync(toEmail, voucherCode, expiryDate);
                return Ok("Voucher email sent successfully!");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // Gửi email xác nhận preorder
        [HttpPost("send-preorder")]
        public async Task<IActionResult> SendPreorderConfirmationEmail(string toEmail, string productName, int quantity)
        {
            try
            {
                await _emailService.SendPreorderConfirmationEmailAsync(toEmail, productName, quantity);
                return Ok("Preorder confirmation email sent successfully!");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }
}
