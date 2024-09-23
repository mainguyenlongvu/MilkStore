using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    public class OrderResponseDTO
    {
        public required string Id { get; set; }
        public required Guid UserId { get; set; }
        public string? VoucherId { get; set; }
        public DateTimeOffset OrderDate { get; set; }
        public required string Status { get; set; }
        public double TotalAmount { get; set; }
        public double DiscountedAmount { get; set; }
        public required string ShippingAddress { get; set; }
        public required string PaymentMethod { get; set; }
        public required string estimatedDeliveryDate { get; set; }
        public DateTimeOffset? deliveryDate { get; set; }

        public IList<OrderDetailResponseDTO> OrderDetailss { get; set; } = new List<OrderDetailResponseDTO>();
    }
}
