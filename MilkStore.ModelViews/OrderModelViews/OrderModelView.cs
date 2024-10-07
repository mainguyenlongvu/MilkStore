using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.OrderModelViews
{    
    public class OrderModelView
    {
        [Required(ErrorMessage = "ShippingAddress không được để trống")]
        public required string ShippingAddress { get; set; }
    }
}
