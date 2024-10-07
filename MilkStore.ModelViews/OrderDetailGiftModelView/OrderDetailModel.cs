using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.OrderDetailGiftModelView
{
    public class OrderDetailGiftModel
    {
        [Required(ErrorMessage = "Id ordergift không được để trống")]
        public required string? OrderGiftId { get; set; }
        [Required(ErrorMessage = "Id gift không được để trống")]
        public required string? GiftId { get; set; }
        public int quantity { get; set; }
    }
}
