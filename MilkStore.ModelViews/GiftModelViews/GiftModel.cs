using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.GiftModelViews
{
    public class GiftModel
    {
        public string Id { get; set; }
        [Required(ErrorMessage = "Giá sp không được để trống")]
        public required int point { get; set; }
        [Required(ErrorMessage = "Name không được để trống")]
        public required string GiftName { get; set; }
        public string ProductId { get; set; }
    }
}
